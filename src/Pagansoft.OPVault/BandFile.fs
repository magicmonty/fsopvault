namespace Pagansoft.OPVault

open System
open FSharp.Results
open FSharp.Results.Results

type BandFileItemData = BandFileItemData of string

type BandFileItem = { Overview: Overview
                      Category: Category
                      Created: DateTime
                      Data: byte array
                      FavoriteOrder: int option
                      FolderId: string option
                      HMAC: byte array
                      EncryptedKeys: byte array
                      IsTrashed: bool
                      TransactionTimeStamp: DateTime option
                      Updated: DateTime option
                      UUID: string }

                    member this.Decrypt (masterKeys: KeyPair) : Result<BandFileItemData, OPVaultError> =
                      let checkKeyData keyData =
                        let calculated = (2 * Crypto.KeySizeInBytes) + Crypto.HMACSizeInBytes + Crypto.IVSizeInBytes
                        let actual = keyData |> Array.length
                        if actual <> calculated
                        then CouldNotDecryptItemKey |> OPDataError |> Result.Error
                        else Ok ()

                      trial {
                        do! checkKeyData this.EncryptedKeys
                        let! keyData = masterKeys.DecryptByteArray true this.EncryptedKeys
                        let itemKey = { EncryptionKey = keyData |> Array.take Crypto.KeySizeInBytes
                                        AuthenticationKey = keyData |> Array.skip Crypto.KeySizeInBytes }

                        let! itemData = this.Data |> OPData.parseBytes
                        let! decryptedData = itemData.Decrypt itemKey

                        return!
                          match decryptedData with
                          | Decrypted data ->  data.PlainText |> String.bytesAsString |> BandFileItemData |> Ok
                          | Encrypted _ -> CouldNotDecryptItem |> OPDataError |> Result.Error
                      }

type BandFile = { Filename: string
                  Items: Map<string, BandFileItem> }

[<RequireQualifiedAccess>]
module BandFile =
  open Chiron
  
  type BandFileItemDTO = { Overview: string
                           Category: string
                           Created: DateTime
                           Data: byte array
                           FavoriteOrder: int option
                           FolderId: string option
                           HMAC: byte array
                           EncryptedKeys: byte array
                           IsTrashed: bool
                           TransactionTimeStamp: DateTime option
                           Updated: DateTime option
                           UUID: string }

                         static member FromJson (_ : BandFileItemDTO) : Json<BandFileItemDTO> =    
                           json {
                               let! (o: string) = Json.read "o"
                               let! (category: string) = Json.read "category"
                               let! (created: int) = Json.read "created"
                               let! (data: string) = Json.read "d"
                               let! (fave: int option) = Json.tryRead "fave"
                               let! (folder: string option) = Json.tryRead "folder"
                               let! (hmac: string) = Json.read "hmac"
                               let! (keys: string) = Json.read "k"
                               let! (trashed: bool option) = Json.tryRead "trashed"
                               let! (tx: int option) = Json.tryRead "tx"
                               let! (updated: int option) = Json.tryRead "updated"
                               let! (uuid: string) = Json.read "uuid"
     
                               return { Overview = o
                                        Category = category
                                        Created = created |> DateTime.fromUnixTimeStamp
                                        Data = data |> ByteArray.fromBase64
                                        FavoriteOrder = fave
                                        FolderId = folder
                                        HMAC = hmac |> ByteArray.fromBase64
                                        EncryptedKeys = keys |> ByteArray.fromBase64
                                        IsTrashed = trashed |> Option.defaultValue false
                                        TransactionTimeStamp = tx |> Option.map DateTime.fromUnixTimeStamp
                                        Updated = updated |> Option.map DateTime.fromUnixTimeStamp
                                        UUID = uuid }
                             }
  let private makeJSON =
    let startMarker = "ld({"
    let endMarker = "});"

    String.makeJSON startMarker endMarker

  let private parseBandItem (overviewKey: KeyPair) (item: BandFileItemDTO) : Result<BandFileItem, OPVaultError> =
    trial {
      let! overview = item.Overview |> Overview.decryptString overviewKey
      let! category = item.Category |> Category.fromCode

      return { Overview = overview
               Category = category
               Created = item.Created
               Data = item.Data
               FavoriteOrder = item.FavoriteOrder
               FolderId = item.FolderId
               HMAC = item.HMAC
               EncryptedKeys = item.EncryptedKeys
               IsTrashed = item.IsTrashed
               TransactionTimeStamp = item.TransactionTimeStamp
               Updated = item.Updated
               UUID = item.UUID }
    }

  let parseBandFileJSON str : Result<Map<string, BandFileItemDTO>, OPVaultError> =
    try
      Json.parse str |> Json.deserialize |> Ok
    with e -> (JSONParserError e.Message) |> Errors.ParserError |> Result.Error

  let readBandFile (profile: DecryptedProfileData) bandfilename = 
    let contents =
      match File.read bandfilename with
      | Ok content ->
        trial {
          let! json = content |> makeJSON
          let! items = json |> parseBandFileJSON
          return! items 
                  |> Map.toList
                  |> List.map (fun (key, item) -> match item |> parseBandItem profile.OverviewKey with
                                                  | Ok item -> Ok (key, item)
                                                  | Result.Error e -> Result.Error e) 
                  |> Result.fold
        } 
      | Result.Error e ->
        match e with
        | FileError (FileNotFound _) -> Ok []
        | _ -> Result.Error e


    match contents  with
    | Ok contents ->  
        Ok { Filename = bandfilename 
             Items = contents |> Map.ofList }
    | Result.Error e -> Result.Error e


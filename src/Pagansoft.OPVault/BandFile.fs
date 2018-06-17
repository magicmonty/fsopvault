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
                      TransactionTimeStamp: DateTime
                      Updated: DateTime
                      UUID: string }

                    member this.Decrypt (masterKeys: KeyPair) : Result<BandFileItemData, OPVaultError> =
                      let checkKeyData keyData =
                        let calculated = (2 * Crypto.KeySizeInBytes) + Crypto.HMACSizeInBytes + Crypto.IVSizeInBytes
                        let actual = keyData |> Array.length
                        if actual <> calculated
                        then CouldNotDecryptItemKey |> OPDataError |> Error
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
                          | Encrypted _ -> CouldNotDecryptItem |> OPDataError |> Error
                      }

type BandFile = { Filename: string
                  Items: Map<string, BandFileItem> }

[<RequireQualifiedAccess>]
module BandFile =
  open Newtonsoft.Json
  
  type BandFileItemDTO = { category: string
                           created: int
                           d: string
                           folder: string
                           hmac: string
                           k: string
                           o: string
                           tx: int
                           updated: int
                           uuid: string 
                           fave: System.Nullable<int>
                           trashed: System.Nullable<bool> }
                            
  let makeJSON =
    let startMarker = "ld({"
    let endMarker = "});"

    String.makeJSON startMarker endMarker

  let parseBandItem (overviewKey: KeyPair) (item: BandFileItemDTO) : Result<BandFileItem, OPVaultError> =
    trial {
      let! overview = item.o |> Overview.decryptString overviewKey
      let! category = item.category |> Category.fromCode

      return { Overview = overview
               Category = category
               Created = item.created |> DateTime.fromUnixTimeStamp
               Data = item.d |> ByteArray.fromBase64
               FavoriteOrder = item.fave |> Option.fromNullable
               FolderId = item.folder |> Option.fromNullableString
               HMAC = item.hmac |> ByteArray.fromBase64
               EncryptedKeys = item.k |> ByteArray.fromBase64
               IsTrashed = item.trashed  |> Option.fromNullable |> Option.defaultValue false
               TransactionTimeStamp = item.tx |> DateTime.fromUnixTimeStamp
               Updated = item.updated |> DateTime.fromUnixTimeStamp
               UUID = item.uuid }
    }

  let parseBandFileJSON str : Result<Map<string, BandFileItemDTO>, OPVaultError> =
    try
      JsonConvert.DeserializeObject<Map<string, BandFileItemDTO>> str 
      |> Ok
    with _ -> (JSONParserError str) |> Errors.ParserError |> Error

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
                                                  | Error e -> Error e) 
                  |> Result.fold
        } 
      | Result.Error e ->
        match e with
        | FileError (FileNotFound _) -> Ok []
        | _ -> Error e


    match contents  with
    | Ok contents ->  
        Ok { Filename = bandfilename 
             Items = contents |> Map.ofList }
    | Error e -> Error e


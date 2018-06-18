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
                      FolderId: UUID option
                      HMAC: byte array
                      EncryptedKeys: byte array
                      IsTrashed: bool
                      TransactionTimeStamp: DateTime
                      Updated: DateTime
                      UUID: UUID }

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
                  Items: Map<UUID, BandFileItem>
                  Keys: UUID seq }

and BandFileItemDTO = { category: string
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

                      member this.ToDomainObject (overviewKey: KeyPair): Result<UUID * BandFileItem, OPVaultError> =
                        trial {
                          let! overview = this.o |> Overview.decryptString overviewKey
                          let! category = this.category |> Category.fromCode
                          let uuid = UUID this.uuid

                          return uuid, { Overview = overview
                                         Category = category
                                         Created = this.created |> DateTime.fromUnixTimeStamp
                                         Data = this.d |> ByteArray.fromBase64
                                         FavoriteOrder = this.fave |> Option.fromNullable
                                         FolderId = this.folder |> Option.fromNullableString |> Option.map UUID
                                         HMAC = this.hmac |> ByteArray.fromBase64
                                         EncryptedKeys = this.k |> ByteArray.fromBase64
                                         IsTrashed = this.trashed  |> Option.fromNullable |> Option.defaultValue false
                                         TransactionTimeStamp = this.tx |> DateTime.fromUnixTimeStamp
                                         Updated = this.updated |> DateTime.fromUnixTimeStamp
                                         UUID = this.uuid |> UUID }
                        }

[<RequireQualifiedAccess>]
module BandFile =
  open ResultOperators

  module private JSON =
    let clean = String.makeJSON "ld({" "});"

    let deserializeDTO = Json.deserialize<Map<string, BandFileItemDTO>>

    let parse (overviewKey: KeyPair) json : Result<Map<UUID, BandFileItem>, OPVaultError> =
      json
      |> deserializeDTO 
      |=> Map.toList
      |=> List.map (snd >> (fun item -> item.ToDomainObject overviewKey))
      |-> Result.fold
      |=> Map.ofList  

  let read (overviewKey: KeyPair) bandfilename = 
    trial {
      let! contents =
        match File.read bandfilename with
        | Ok content ->
            content
            |> JSON.clean
            |-> JSON.parse overviewKey
        | Result.Error e ->
          match e with
          | FileError (FileNotFound _) -> Ok Map.empty
          | _ -> Error e
    
      return { Filename = bandfilename 
               Items = contents
               Keys = contents |> Map.toSeq |> Seq.map fst }
    }


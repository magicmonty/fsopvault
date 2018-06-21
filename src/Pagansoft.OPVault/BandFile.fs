namespace Pagansoft.OPVault

open System
open FSharp.Results
open FSharp.Results.Results

type BandFileItemMetaData = { Overview: Overview
                              Category: Category
                              Created: DateTime
                              FavoriteOrder: int option
                              FolderId: UUID option
                              IsTrashed: bool
                              TransactionTimeStamp: DateTime
                              Updated: DateTime
                              UUID: UUID }

type BandFileItemKey = { HMAC: byte array
                         EncryptedKeys: byte array }
        
                       member this.Decrypt (masterKeys: KeyPair) : Result<KeyPair, OPVaultError> =
                         let checkKeyData keyData =
                           let calculated = (2 * Crypto.KeySizeInBytes) + Crypto.HMACSizeInBytes + Crypto.IVSizeInBytes
                           let actual = keyData |> Array.length
                           if actual <> calculated
                           then CouldNotDecryptItemKey |> OPDataError |> Error
                           else Ok ()
                         trial {
                           do! checkKeyData this.EncryptedKeys
                           let! keyData = masterKeys.DecryptByteArray true this.EncryptedKeys
                           return { EncryptionKey = keyData |> Array.take Crypto.KeySizeInBytes
                                    AuthenticationKey = keyData |> Array.skip Crypto.KeySizeInBytes }
                         }

type BandFileItemData =
  | EncryptedBandFileItemData of byte array
  | DecryptedBandFileItemData of Item

  member this.Decrypt (itemKey: KeyPair) =
    match this with
    | DecryptedBandFileItemData _ -> Ok this
    | EncryptedBandFileItemData data ->
      trial {
        let! encrypted = data |> OPData.parseBytes
        let! decrypted = encrypted.Decrypt itemKey
        let! plainText = decrypted.PlainTextAsString ()
        let! item = Item.deserialize plainText

        return item |> DecryptedBandFileItemData
      }

type BandFileItem = { MetaData: BandFileItemMetaData
                      ItemKey: BandFileItemKey
                      Data: BandFileItemData }
        
                    member this.Decrypt (masterKeys: KeyPair) : Result<BandFileItem, OPVaultError> =
                      match this.Data with
                      | DecryptedBandFileItemData _ -> Ok this
                      | EncryptedBandFileItemData _ ->
                        trial {
                          let! itemKey = this.ItemKey.Decrypt masterKeys
                          let! decryptedData = this.Data.Decrypt itemKey
                         
                          return { this with Data = decryptedData }
                        }

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
        
                       member this.ToDomainObject (overviewKey: KeyPair): Result<UUID * BandFileItem, OPVaultError> =
                         trial {
                           let! overview = this.o |> Overview.decryptString overviewKey
                           let! category = this.category |> Category.fromCode
                           let uuid = UUID this.uuid
        
                           return uuid, { MetaData =  { Overview = overview
                                                        Category = category
                                                        Created = this.created |> DateTime.fromUnixTimeStamp
                                                        FavoriteOrder = this.fave |> Option.fromNullable
                                                        FolderId = this.folder |> Option.fromNullableString |> Option.map UUID
                                                        IsTrashed = this.trashed  |> Option.fromNullable |> Option.defaultValue false
                                                        TransactionTimeStamp = this.tx |> DateTime.fromUnixTimeStamp
                                                        Updated = this.updated |> DateTime.fromUnixTimeStamp
                                                        UUID = this.uuid |> UUID }
                                          ItemKey = { HMAC = this.hmac |> ByteArray.fromBase64
                                                      EncryptedKeys = this.k |> ByteArray.fromBase64 }
                                          Data = this.d |> ByteArray.fromBase64 |> EncryptedBandFileItemData }
                         }
        
type BandFile = { Filename: string
                  Items: Map<UUID, BandFileItem>
                  Keys: UUID seq }

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
    if System.IO.File.Exists bandfilename
    then
      trial {
        let! json = File.read bandfilename
        let! contents = json |> JSON.clean |-> JSON.parse overviewKey      
        return { Filename = bandfilename 
                 Items = contents
                 Keys = contents |> Map.toSeq |> Seq.map fst }
      }
    else
      Ok { Filename = bandfilename
           Items = Map.empty 
           Keys = [] }

  let readAll (overviewKey: KeyPair) baseDir =
    [ 0 .. 15 ]
    |> List.map ((sprintf "%s/band_%X.js" baseDir) >> (read overviewKey))
    |> Result.fold


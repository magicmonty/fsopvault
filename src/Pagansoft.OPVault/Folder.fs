namespace Pagansoft.OPVault

open System
open FSharp.Results
open FSharp.Results.Results

type Folder = { UUID: UUID
                Overview: string
                Created: DateTime
                TransactionTimeStamp: DateTime
                Updated: DateTime 
                IsSmartFolder: bool }

and FolderDTO = { uuid: string
                  overview: string
                  created: int
                  tx: int
                  updated: int
                  smart: System.Nullable<bool> }
                
                member this.ToDomainObject (overviewKey: KeyPair) : Result<UUID * Folder, OPVaultError> =
                  trial {
                    let! overview = this.overview |> ByteArray.fromBase64 |> overviewKey.DecryptByteArray false
                    let uuid = UUID this.uuid
                    return uuid, { UUID = uuid
                                   Overview = overview |> Array.skipWhile (fun b -> b = 0uy) |> String.bytesAsString
                                   Created = this.created |> DateTime.fromUnixTimeStamp
                                   TransactionTimeStamp = this.tx |> DateTime.fromUnixTimeStamp
                                   Updated = this.updated |> DateTime.fromUnixTimeStamp
                                   IsSmartFolder = this.smart |> Option.fromNullable |> Option.defaultValue false }
                  }

module Folder =
  open ResultOperators

  module JSON =
    let clean = String.makeJSON "loadFolders({" "});"

    let deserializeDTO = Json.deserialize<Map<string, FolderDTO>>

    let parse (overviewKey: KeyPair) (json: string) : Result<Map<UUID, Folder>, OPVaultError> =
      json 
      |> deserializeDTO
      |=> Map.toList 
      |=> List.map (snd >> (fun item -> item.ToDomainObject overviewKey))
      |-> Result.fold
      |=> Map.ofList
      
  let read (overviewKey: KeyPair) (vaultDir: string) =
    let filename = sprintf "%s/folders.js" vaultDir
    match File.read filename with
    | Ok content ->
      trial {
        let! json = content |> JSON.clean
        return! json |> JSON.parse overviewKey
      } 
    | Error e ->
      match e with
      | FileError (FileNotFound _) -> Ok Map.empty
      | _ -> Error e
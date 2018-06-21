namespace Pagansoft.OPVault

open FSharp.Results.Results
open ResultOperators
open FSharp.Results

type LockedVault = { VaultDir: string }

                    member this.Unlock password =
                      let decryptProfile () = 
                        Profile.read (sprintf "%s/profile.js" this.VaultDir)
                        |-> Profile.decrypt password
                        |-> Profile.getDecryptedProfileData 
                       
                      trial {
                        let! profileData = decryptProfile()
                        let! bandFiles = BandFile.readAll profileData.OverviewKey this.VaultDir
                        let! folders = Folder.read profileData.OverviewKey this.VaultDir 
  
                        return { VaultDir = this.VaultDir
                                 Profile = profileData
                                 BandFiles = bandFiles
                                 Folders = folders }
                      }
                      
and UnlockedVault = { VaultDir: string
                      Profile: DecryptedProfileData
                      BandFiles: BandFile list
                      Folders: Map<UUID, Folder> }
                    
                    member this.Items = 
                      this.BandFiles 
                      |> List.collect (fun f -> f.Items |> Map.toList) 
                      |> Map.ofList
                      
                    member this.Titles =
                      this.Items 
                      |> Map.toList
                      |> List.map (snd >> (fun i -> i.MetaData.UUID, (i.MetaData.Overview.Title |> Option.defaultValue "")))

                    member this.Lock () =
                      { VaultDir = this.VaultDir }                      

type Vault =
  | LockedVault of LockedVault
  | UnlockedVault of UnlockedVault

[<RequireQualifiedAccess>]
module Vault =
  let unlock password vault =
    match vault with
    | UnlockedVault v -> Ok vault
    | LockedVault v -> v.Unlock password |=> UnlockedVault

  let lock vault =
    match vault with
    | UnlockedVault v -> v.Lock () |> LockedVault
    | LockedVault v -> LockedVault v 

  let getKeysByTitle (title: string) vault =
    match vault with
    | LockedVault _ -> VaultIsLocked |> VaultError |> Error
    | UnlockedVault v ->
      let cleanedTitle = title.ToUpperInvariant().Trim()

      v.Titles
      |> List.filter (fun (_, title) -> match title.ToUpperInvariant().Trim() with
                                        | "" -> cleanedTitle = ""
                                        | t -> t.Contains(cleanedTitle))
      |> Ok

  let getItemsByTitle (title: string) vault =
    match vault with
    | LockedVault _ -> VaultIsLocked |> VaultError |> Error
    | UnlockedVault v ->
      vault
      |> getKeysByTitle title
      |> Result.defaultValue []
      |> List.map (fun (key, _) -> v.Items.[key].Decrypt v.Profile.MasterKey)
      |> Ok

  let getItemByUUID (uuid: UUID) vault =
    match vault with
    | LockedVault _ -> VaultIsLocked |> VaultError |> Error
    | UnlockedVault v -> v.Items.[uuid].Decrypt v.Profile.MasterKey
namespace Pagansoft.OPVault

open FSharp.Results.Results
open ResultOperators

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
                      
                    member this.Keys = 
                      this.BandFiles 
                      |> List.collect (fun f -> f.Items |> Map.toList)
                      |> List.map fst

                    member this.Lock () =
                      { VaultDir = this.VaultDir }


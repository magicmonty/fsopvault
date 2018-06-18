namespace Pagansoft.OPVault

open FSharp.Results.Results

type LockedVault = { VaultDir: string }

                    member this.Unlock password =
                      trial {
                        let! encryptedProfile = Profile.read (sprintf "%s/profile.js" this.VaultDir)
                        let! decryptedProfile = Profile.decrypt password encryptedProfile
                        let! profileData = decryptedProfile |> Profile.getDecryptedProfileData 
                        let! bandFiles =
                          [ for i in 0 .. 15 -> 
                              let bandNumber = (sprintf "%x" i).ToUpper()
                              let filename = sprintf "%s/band_%s.js" this.VaultDir bandNumber
                              filename |> BandFile.read profileData.OverviewKey ] 
                          |> FSharp.Results.Result.fold
                        let items = bandFiles |> List.collect (fun f -> f.Items |> Map.toList)
                        let! folders = Folder.read profileData.OverviewKey this.VaultDir 
  
                        return { VaultDir = this.VaultDir
                                 Profile = profileData
                                 Items = items |> Map.ofList
                                 Folders = folders }
                      }
                      
and UnlockedVault = { VaultDir: string
                      Profile: DecryptedProfileData
                      Items: Map<UUID, BandFileItem>
                      Folders: Map<UUID, Folder> }
                    
                    member this.Lock () =
                      { VaultDir = this.VaultDir }


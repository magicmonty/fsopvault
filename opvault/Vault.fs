namespace OPVault

open FSharp.Results.Result

type LockedVault = { VaultDir: string }

                    member this.Unlock password =
                      trial {
                        let! encryptedProfile = Profile.read (sprintf "%s/profile.js" this.VaultDir)
                        let! decryptedProfile = Profile.decrypt password encryptedProfile
                        let! profileData = decryptedProfile |> Profile.getDecryptedProfileData 
                        let! bandFiles =
                          [ for i in 0 .. 15 -> 
                              let bandNumber = (sprintf "%x" i).ToUpper()
                              let filename = sprintf "%s\\band_%s.js" this.VaultDir bandNumber
                              filename |> BandFile.readBandFile profileData ] 
                          |> FSharp.Results.Result.fold
  
                        return { VaultDir = this.VaultDir
                                 Profile = profileData
                                 BandFiles = bandFiles }
                      }
                      
and UnlockedVault = { VaultDir: string
                      Profile: DecryptedProfileData
                      BandFiles: BandFile list }
                    
                    member this.Lock () =
                      { VaultDir = this.VaultDir }


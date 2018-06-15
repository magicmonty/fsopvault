#load @"../.paket/load/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#load @"../.paket/load/netstandard2.0/FSharp.Data.fsx"

#load "Errors.fs"
#load "Crypto.fs"
#load "Helpers.fs"
#load "File.fs"
#load "ResultModule.fs"
#load "BinaryParser.fs"
#load "OPData.fs"
#load "Profile.fs"
#load "Overview.fs"
#load "Category.fs"
#load "BandFile.fs"
#load "Folder.fs"
#load "Vault.fs"

open OPVault
open FSharp.Results
open Result

let password = "freddy"
let vault = { VaultDir = "testdata\\onepassword_data\\default" }
let unlockedVault = vault.Unlock password

trial {
  let! unlocked = unlockedVault
  let! items =    
    unlocked.BandFiles
    |> List.collect (fun f -> f.Items)
    |> List.map (fun f -> f.Decrypt unlocked.Profile.MasterKey)
    |> Result.fold

  return items |> List.map (fun f -> match f with BandFileItemData d -> d)
}


#load @"../.paket/load/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#load @"../.paket/load/netstandard2.0/FSharp.Data.fsx"

#load "Errors.fs"
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
open FSharp.Results.Result

let password = "freddy"
let vault = { VaultDir = "testdata\\onepassword_data\\default" }
let unlockedVault = vault.Unlock password

let folder =
  trial {
    let! unlocked = unlockedVault
    let! items = Folder.read unlocked.Profile unlocked.VaultDir
    return 
      items 
      |> List.last 
      |> fun i -> i.Overview
  } |> Result.defaultValue ""

folder
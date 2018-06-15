#load @"../.paket/load/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#load @"../.paket/load/netstandard2.0/FSharp.Data.fsx"

#load "../src/Pagansoft.OPVault/Errors.fs"
#load "../src/Pagansoft.OPVault/Crypto.fs"
#load "../src/Pagansoft.OPVault/Helpers.fs"
#load "../src/Pagansoft.OPVault/File.fs"
#load "../src/Pagansoft.OPVault/ResultModule.fs"
#load "../src/Pagansoft.OPVault/BinaryParser.fs"
#load "../src/Pagansoft.OPVault/OPData.fs"
#load "../src/Pagansoft.OPVault/Profile.fs"
#load "../src/Pagansoft.OPVault/Overview.fs"
#load "../src/Pagansoft.OPVault/Category.fs"
#load "../src/Pagansoft.OPVault/BandFile.fs"
#load "../src/Pagansoft.OPVault/Folder.fs"
#load "../src/Pagansoft.OPVault/Vault.fs"

open Pagansoft.OPVault
open FSharp.Results
open FSharp.Results.Results

let password = "freddy"
let vault = { VaultDir = "test/testdata/onepassword_data/default" }
let unlockedVault = vault.Unlock password

trial {
  let! unlocked = unlockedVault
  let! items =    
    unlocked.BandFiles
    |> List.collect (fun f -> f.Items)
    |> List.map (fun f -> f.Decrypt unlocked.Profile.MasterKey)
    |> Result.fold

  return items |> List.map (fun f -> match f with BandFileItemData d -> d)
} |> Result.defaultValue []
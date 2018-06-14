namespace OPVault

[<RequireQualifiedAccess>]
module File =
  open Errors
  
  let read filename = 
    try
      Ok (System.IO.File.ReadAllText filename)
    with
    | :? System.IO.FileNotFoundException -> FileNotFound filename |> FileError |> Error
    | :? System.IO.DirectoryNotFoundException -> FileNotFound filename |> FileError |> Error
    | e -> UnknownError (sprintf "%s: %s" ((e.GetType()).Name) e.Message) |> Error

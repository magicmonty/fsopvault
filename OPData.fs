namespace OPVault

#if INTERACTIVE
#load @".paket/load/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#endif

open System.Security.Cryptography
open System.IO

type AuthenticationResult =
  | SuccessfullyAuthenticated of KeyPair * OPData
  | CouldNotDeriveKeys
  | CouldReadProfile
  | AuthenticationFailed

and OPData = { PlainTextSize: uint64
               PaddingSize: uint64
               IV: byte array
               CipherText: byte array
               HMAC: byte array }

               member this.HashBytes : byte array =
                 Array.concat [| "opdata01".ToCharArray() |> Array.map byte
                                 System.BitConverter.GetBytes(this.PlainTextSize)
                                 this.IV
                                 this.CipherText |]

               member this.Authenticate (keys: KeyPair) =
                 if (keys.Hmac this.HashBytes) = this.HMAC
                 then SuccessfullyAuthenticated (keys, this)
                 else AuthenticationFailed

and KeyPair = { EncryptionKey: byte array
                AuthenticationKey: byte array }
                 
                member this.Hmac (bytes: byte array) = 
                  use hmac = new HMACSHA256(this.AuthenticationKey)
                  hmac.ComputeHash(bytes)
                 
                member this.Decryptor iv =
                  let mutable aes = new RijndaelManaged()
                  aes.Key <- this.EncryptionKey
                  aes.Mode <- CipherMode.CBC
                  aes.KeySize <- 256
                  aes.IV <- iv
                  aes.Padding <- PaddingMode.None
                  aes

module KeyPair =
  open Microsoft.AspNetCore.Cryptography.KeyDerivation
  open BinaryParser
  open System
  
  let private KeySize = 256 / 8

  let private parse binaryReader =
    let parser = parseBinary {
      let! enc = Take KeySize
      let! auth = Take KeySize
      return { EncryptionKey = enc
               AuthenticationKey = auth }
    }

    match parser.Function binaryReader with
    | Success (v, _) -> Ok v
    | Failure (_, e) -> Error e

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let parseBase64String data =
    Convert.FromBase64String(data) |> parseBytes

  let deriveFromMasterPassword (password: string) salt iterations =
    KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA512, iterations, KeySize * 2) |> parseBytes

module OPData =
  open BinaryParser
  open System

  let private parse binaryReader = 
    let parser = parseBinary {
      let! _ = ATag "opdata01"
      let! plainTextSize = RUnsignedLong
      let paddingSize = 16UL - (plainTextSize % 16UL)
      let! iv = Take 16
      let! cipherText = Take (paddingSize + plainTextSize |> int)
      let! hmac = Take (256 / 8)

      return { PlainTextSize = plainTextSize
               PaddingSize = paddingSize
               IV = iv
               CipherText = cipherText
               HMAC = hmac }
    }

    match parser.Function binaryReader with
    | Success (v, _) -> Ok v
    | Failure (_, e) -> Error e

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let parseBase64String data =
    Convert.FromBase64String(data) |> parseBytes

  let parseRawFile fileName = System.IO.File.ReadAllBytes fileName |> parseBytes

  let authenticate (keys: KeyPair) (data: OPData) = 
    data.Authenticate keys

  let authenticateRawFile (keys: KeyPair) filename =
    match parseRawFile filename with
    | Ok data -> data.Authenticate keys
    | _ -> AuthenticationFailed

  let authenticateRawFileWithPassword (password: string) (salt: byte array) (iterations: int) filename =
    match KeyPair.deriveFromMasterPassword password salt iterations with
    | Ok keys -> authenticateRawFile keys filename
    | _ -> CouldNotDeriveKeys

module TestKeyPair =
  let authenticateResult = 
    match Profile.read "testdata\\profile.js" with
    | Ok profile ->
      let password = "freddy"
      let filename = "testData\\full_padding.opdata01"
      filename |> OPData.authenticateRawFileWithPassword password profile.Salt profile.Iterations
    | _ -> CouldReadProfile

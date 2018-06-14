namespace OPVault

open System.Security.Cryptography
open System.IO
open System
open Errors

type OPData = { PlainTextSize: uint64
                PaddingSize: uint64
                IV: byte array
                CipherText: byte array
                PlainText: byte array option
                DecryptedKeys: KeyPair option
                HMAC: byte array }
 
                member this.HashBytes : byte array =
                  Array.concat [| "opdata01".ToCharArray() |> Array.map byte
                                  System.BitConverter.GetBytes(this.PlainTextSize)
                                  this.IV
                                  this.CipherText |]
 
                member this.Authenticate (keys: KeyPair) =
                  let calculatedHMAC = keys.Hmac this.HashBytes
                  if calculatedHMAC = this.HMAC
                  then Ok ()
                  else 
                    printfn "Should be %A" this.HMAC
                    printfn "but was %A" calculatedHMAC
                    CouldNotAuthenticate |> OPDataError |> Error

and KeyPair = { EncryptionKey: byte array
                AuthenticationKey: byte array }
                 
                member this.Hmac (bytes: byte array) = 
                  use hmac = new HMACSHA256(this.AuthenticationKey)
                  hmac.ComputeHash(bytes)
                 
                member this.Decrypt data =
                  match data.CipherText with
                  | [||] -> EmptyCipherText |> OPDataError |> Error
                  | _ ->
                    use decryptor = System.Security.Cryptography.Aes.Create()
                    decryptor.KeySize <- 256
                    decryptor.Mode <- CipherMode.CBC
                    decryptor.IV <- data.IV
                    decryptor.Key <- this.EncryptionKey
                    decryptor.Padding <- PaddingMode.None
                  
                    use msDecrypt = new MemoryStream(data.CipherText)
                    use csDecrypt = new CryptoStream(msDecrypt, decryptor.CreateDecryptor(), CryptoStreamMode.Read)
                    use dsDecrypt = new MemoryStream()
                    csDecrypt.CopyTo(dsDecrypt)
                    let plaintext = (dsDecrypt.GetBuffer() |> Array.skip (int data.PaddingSize) |> Array.take (int data.PlainTextSize))
                    let hash = 
                      use h = new SHA512Managed()
                      h.ComputeHash plaintext
                    
                    let keyPair = { EncryptionKey = hash |> Array.take 32
                                    AuthenticationKey = hash |> Array.skip 32 }
                    
                    Ok { data with DecryptedKeys = Some keyPair
                                   PlainText = Some plaintext }
                
[<RequireQualifiedAccess>]
module KeyPair =
  open Microsoft.AspNetCore.Cryptography.KeyDerivation
  open BinaryParser
  
  let empty = { EncryptionKey = [||]
                AuthenticationKey = [||] }

  let private KeySize = 256 / 8 // 256 bits

  let private parse binaryReader =
    let parser = parseBinary {
      let! enc = Take KeySize
      let! auth = Take KeySize
      return { EncryptionKey = enc
               AuthenticationKey = auth }
    }

    match parser.Function binaryReader with
    | Ok (v, _) -> Ok v
    | Error e -> Error e

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let parseBase64String data =
    Convert.FromBase64String(data) |> parseBytes

  let deriveFromMasterPassword (password: string) salt iterations =
    KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA512, iterations, KeySize * 2) |> parseBytes

[<RequireQualifiedAccess>]
module OPData =
  open BinaryParser
  open FSharp.Results.Result

  let empty =  { PlainTextSize = 0UL
                 PaddingSize = 0UL
                 IV = [||]
                 CipherText = [||]
                 PlainText = None
                 DecryptedKeys = None
                 HMAC = [||] }

  let private parse binaryReader =     
    trial { 
      let parser = parseBinary {
        let! _ = ATag "opdata01"
        let! plainTextSize = RUnsignedLong
        let paddingSize = 16UL - (plainTextSize % 16UL)
        let! iv = Take 16
        let! cipherText = Take (paddingSize + plainTextSize |> int)
        let! hmac = Take (256 / 8)
        let! _ = EOF

        return { PlainTextSize = plainTextSize
                 PaddingSize = paddingSize
                 IV = iv
                 CipherText = cipherText
                 PlainText = None
                 DecryptedKeys = None
                 HMAC = hmac }
      }
      let! v, _ = parser.Function binaryReader
      return v
    }

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let parseBase64String data =
    Convert.FromBase64String(data) |> parseBytes

  let authenticate (keys: KeyPair) (data: OPData) = 
    data.Authenticate keys

  let authenticateAndDecrypt (keys: KeyPair) (data: OPData) =
    trial {
      do! authenticate keys data
      return! keys.Decrypt data
    }

  let getPlainText (data: OPData) =
    match data.PlainText with
    | Some plaintext -> Ok (sprintf "%s" (System.Text.Encoding.UTF8.GetString plaintext))
    | None -> OPDataIsNotDecrypted |> OPDataError |> Error

  let getDecryptedKeys (data: OPData) =
    match data.DecryptedKeys with
    | Some keys -> Ok keys
    | None -> OPDataIsNotDecrypted |> OPDataError |> Error


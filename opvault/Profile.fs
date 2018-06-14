namespace OPVault

open Errors

type EncryptedProfileData = { LastUpdatedBy: string option
                              UpdatedAt: System.DateTime option
                              ProfileName: string
                              Salt: byte array
                              MasterKey: byte array
                              OverviewKey: byte array
                              Iterations: int
                              UUID: string
                              CreatedAt: System.DateTime }

type DecryptedProfileData = { LastUpdatedBy: string option
                              UpdatedAt: System.DateTime option
                              ProfileName: string
                              Salt: byte array
                              MasterKey: KeyPair
                              OverviewKey: KeyPair
                              Iterations: int
                              UUID: string
                              CreatedAt: System.DateTime }

type Profile = 
  | EncryptedProfile of EncryptedProfileData
  | DecryptedProfile of DecryptedProfileData

[<RequireQualifiedAccess>]
module Profile =
  open System
  open FSharp.Data
  open FSharp.Results.Result

  let empty = 
    { LastUpdatedBy = None
      UpdatedAt = None
      ProfileName = "default"
      Salt = [| for _ in 1 .. 16 -> 0uy |]
      MasterKey = KeyPair.empty
      OverviewKey = KeyPair.empty
      Iterations = 50000
      UUID = "00000000000000000000000000000000"
      CreatedAt = DateTime.Now }

  type private ProfileJson = JsonProvider<""" [{"lastUpdatedBy":"FOO","updatedAt":1370323483,"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414},{"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414}] """, SampleIsList=true>

  let private startMarker = "varprofile={"
  let private endMarker = "};"

  let private profileError error = error |> ProfileError |> Error

  let private makeJSONText = String.makeJSON startMarker endMarker

  let private parseProfileJSON (json: string) =
    try
      Ok (ProfileJson.Parse json)
    with
    | e -> JSONParserError e.Message |> ParserError |> Error

  let read filename =
    trial {
      let! content = File.read filename
      let! content = makeJSONText content
      let! json = content |> parseProfileJSON
      return EncryptedProfile 
        { LastUpdatedBy = json.LastUpdatedBy
          UpdatedAt = json.UpdatedAt |> Option.map DateTime.fromUnixTimeStamp
          ProfileName = json.ProfileName
          Salt = json.Salt |> ByteArray.fromBase64
          MasterKey = json.MasterKey |> ByteArray.fromBase64
          OverviewKey = json.OverviewKey |> ByteArray.fromBase64
          Iterations = json.Iterations
          UUID = json.Uuid
          CreatedAt = json.CreatedAt |> DateTime.fromUnixTimeStamp } 
    }

  let getDecryptedProfileData profile =
    match profile with
    | DecryptedProfile profileData -> Ok profileData
    | _ -> profileError ProfileIsEncrypted
    
  let getDecryptedOverviewKey profile =
    match profile with
    | EncryptedProfile _ -> profileError ProfileIsEncrypted
    | DecryptedProfile profile -> Ok profile.OverviewKey

  let getDecryptedMasterKey profile =
    match profile with
    | EncryptedProfile _ -> profileError ProfileIsEncrypted
    | DecryptedProfile profile -> Ok profile.MasterKey

  let private decryptKey getEncryptedKeyData (derivedKeys: KeyPair) (encryptedProfileData: EncryptedProfileData) = 
    trial {
      let! encryptedKeyData = encryptedProfileData |> getEncryptedKeyData |> OPData.parseBytes
      let! decryptedKeyData = derivedKeys.Decrypt encryptedKeyData
      return! decryptedKeyData |> OPData.getDecryptedKeys
    }

  let private decryptMasterKey = decryptKey (fun p -> p.MasterKey)
  let private decryptOverviewKey = decryptKey (fun p -> p.OverviewKey)

  let decrypt password (profile: Profile) =
    match profile with
    | DecryptedProfile _ -> Ok profile
    | EncryptedProfile encryptedProfile ->
      trial {
        let! derivedKeys = KeyPair.deriveFromMasterPassword password encryptedProfile.Salt encryptedProfile.Iterations
        let! masterKey = decryptMasterKey derivedKeys encryptedProfile
        let! overviewKey = decryptOverviewKey derivedKeys encryptedProfile

        return DecryptedProfile
          { LastUpdatedBy = encryptedProfile.LastUpdatedBy
            UpdatedAt = encryptedProfile.UpdatedAt
            ProfileName = encryptedProfile.ProfileName
            Salt = encryptedProfile.Salt
            MasterKey = masterKey
            OverviewKey = overviewKey
            Iterations = encryptedProfile.Iterations
            UUID = encryptedProfile.UUID
            CreatedAt = encryptedProfile.CreatedAt }
      }
  
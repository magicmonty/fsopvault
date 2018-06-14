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
  open System.IO
  open FSharp.Data
  open FSharp.Results.Result

  type ProfileJson = JsonProvider<""" [{"lastUpdatedBy":"FOO","updatedAt":1370323483,"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414},{"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414}] """, SampleIsList=true>

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

  let read filename =
    try
      let content = 
        (File.ReadAllText filename)
          .Replace("\r\n","")
          .Replace("\r","")
          .Replace("\n","")
          .Replace(" ", "")
          .Replace("\t","")
          .Trim()

      let startMarker = "varprofile={"
      let endMarker = "};"

      if content.StartsWith(startMarker) && content.EndsWith(endMarker)
      then
        let json = content.Substring (startMarker |> String.length)
        let json = json.Substring (0, (json |> String.length) - (endMarker |> String.length))
        let json = sprintf "{%s}" json
        let json = ProfileJson.Parse json

        let fromUnixTimeStamp (value: int) = 
          let dtDateTime = DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)
          (dtDateTime.AddSeconds (float value)).ToLocalTime()
        
        let fromBase64 (value: string) : byte array =
          Convert.FromBase64String value

        let encrypted : EncryptedProfileData =
          { LastUpdatedBy = json.LastUpdatedBy
            UpdatedAt = json.UpdatedAt |> Option.map fromUnixTimeStamp
            ProfileName = json.ProfileName
            Salt = json.Salt |> fromBase64
            MasterKey = json.MasterKey |> fromBase64
            OverviewKey = json.OverviewKey |> fromBase64
            Iterations = json.Iterations
            UUID = json.Uuid
            CreatedAt = json.CreatedAt |> fromUnixTimeStamp } 
        
        encrypted |> EncryptedProfile |> Ok

      else CouldNotReadProfile |> ProfileError |> Error
    with
    | :? System.IO.FileNotFoundException -> ProfileNotFound |> ProfileError |> Error
    | e -> e.Message |> UnknownProfileError  |> ProfileError |> Error

  let getDecryptedOverviewKey profile =
    match profile with
    | EncryptedProfile _ -> ProfileIsEncrypted |> ProfileError |> Error
    | DecryptedProfile profile -> Ok profile.OverviewKey

  let getDecryptedMasterKey profile =
    match profile with
    | EncryptedProfile _ -> ProfileIsEncrypted |> ProfileError |> Error
    | DecryptedProfile profile -> Ok profile.MasterKey

  let decrypt password (profile: Profile) =
    match profile with
    | DecryptedProfile _ -> Ok profile
    | EncryptedProfile encryptedProfile ->
      trial {
        let! derivedKeys = KeyPair.deriveFromMasterPassword password encryptedProfile.Salt encryptedProfile.Iterations
        let! encryptedMasterKeyData = encryptedProfile.MasterKey |> OPData.parseBytes
        let! decryptedMasterKeyData = derivedKeys.Decrypt encryptedMasterKeyData
        let! masterKey = decryptedMasterKeyData |> OPData.getDecryptedKeys

        let! encryptedOverviewKeyData = encryptedProfile.OverviewKey |> OPData.parseBytes
        let! decryptedOverviewKeyData = derivedKeys.Decrypt encryptedOverviewKeyData
        let! overviewKey = decryptedOverviewKeyData |> OPData.getDecryptedKeys

        let decrypted : DecryptedProfileData =
          { LastUpdatedBy = encryptedProfile.LastUpdatedBy
            UpdatedAt = encryptedProfile.UpdatedAt
            ProfileName = encryptedProfile.ProfileName
            Salt = encryptedProfile.Salt
            MasterKey = masterKey
            OverviewKey = overviewKey
            Iterations = encryptedProfile.Iterations
            UUID = encryptedProfile.UUID
            CreatedAt = encryptedProfile.CreatedAt }
        return DecryptedProfile decrypted }
  
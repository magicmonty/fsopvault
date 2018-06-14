namespace OPVault

#if INTERACTIVE
#load @".paket/load/netstandard2.0/FSharp.Data.fsx"
#endif

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
                              MasterKey: OPData
                              OverviewKey: OPData
                              Iterations: int
                              UUID: string
                              CreatedAt: System.DateTime }

type Profile = 
  | EncryptedProfile of EncryptedProfileData
  | DecryptedProfile of DecryptedProfileData

module Profile =
  open System
  open System.IO
  open FSharp.Data

  type ProfileJson = JsonProvider<""" [{"lastUpdatedBy":"FOO","updatedAt":1370323483,"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414},{"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414}] """, SampleIsList=true>

  let empty = 
    { LastUpdatedBy = None
      UpdatedAt = None
      ProfileName = "default"
      Salt = [| for _ in 1 .. 16 -> 0uy |]
      MasterKey = OPData.empty
      OverviewKey = OPData.empty
      Iterations = 50000
      UUID = "00000000000000000000000000000000"
      CreatedAt = DateTime.Now }

  let read filename =
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

    else Error "Could not read profile!"

  let decrypt password (profile: Profile) =
    match profile with
    | DecryptedProfile _ -> Ok profile
    | EncryptedProfile profile ->
      match KeyPair.deriveFromMasterPassword password profile.Salt profile.Iterations with
      | Ok keys ->
        match OPData.parseBytes profile.MasterKey with
        | Ok masterKey -> 
          match OPData.authenticateAndDecrypt keys masterKey with
          | DecryptionSuccess masterKey -> 
            match OPData.parseBytes profile.OverviewKey with
            | Ok overviewKey -> 
              match OPData.authenticateAndDecrypt keys overviewKey with
              | DecryptionSuccess overviewKey -> 
                let decrypted : DecryptedProfileData =
                  { LastUpdatedBy = profile.LastUpdatedBy
                    UpdatedAt = profile.UpdatedAt
                    ProfileName = profile.ProfileName
                    Salt = profile.Salt
                    MasterKey = masterKey
                    OverviewKey = overviewKey
                    Iterations = profile.Iterations
                    UUID = profile.UUID
                    CreatedAt = profile.CreatedAt }
                decrypted |> DecryptedProfile |> Ok
              | _ -> Error "Could not decrypt overview key!"
            | Error e -> Error e
          | _ -> Error "Could not decrypt master key!"
        | Error e -> Error e
      | Error e -> Error e

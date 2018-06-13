namespace OPVault

#if INTERACTIVE
#load @".paket/load/netstandard2.0/FSharp.Data.fsx"
#endif

type Profile = { LastUpdatedBy: string option
                 UpdatedAt: System.DateTime option
                 ProfileName: string
                 Salt: byte array
                 MasterKey: byte array
                 OverviewKey: byte array
                 Iterations: int
                 UUID: string
                 CreatedAt: System.DateTime }

module Profile =
  open System
  open System.IO
  open FSharp.Data

  type ProfileJson = JsonProvider<""" [{"lastUpdatedBy":"FOO","updatedAt":1370323483,"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414},{"profileName":"FOO","salt":"FOO","masterKey":"FOO","iterations":50000,"uuid":"FOO","overviewKey":"FOO","createdAt":1373753414}] """, SampleIsList=true>

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

      Ok { LastUpdatedBy = json.LastUpdatedBy
           UpdatedAt = json.UpdatedAt |> Option.map fromUnixTimeStamp
           ProfileName = json.ProfileName
           Salt = json.Salt |> fromBase64
           MasterKey = json.MasterKey |> fromBase64
           OverviewKey = json.OverviewKey |> fromBase64
           Iterations = json.Iterations
           UUID = json.Uuid
           CreatedAt = json.CreatedAt |> fromUnixTimeStamp }

    else Error "Could not read profile!"


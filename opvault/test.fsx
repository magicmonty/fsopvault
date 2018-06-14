#load @"../.paket/load/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#load @"../.paket/load/netstandard2.0/FSharp.Data.fsx"

#load "Errors.fs"
#load "Helpers.fs"
#load "File.fs"
#load "ResultModule.fs"
#load "BinaryParser.fs"
#load "OPData.fs"
#load "Profile.fs"

open OPVault
open Errors
open FSharp.Results.Result
open FSharp.Data
open FSharp.Data.JsonExtensions


let getOverview overviewKey (encryptedOverview: byte array) =
  trial {
    let! encryptedOverviewData = encryptedOverview |> OPData.parseBytes
    let! decryptedOverviewData = encryptedOverviewData |> OPData.authenticateAndDecrypt overviewKey
    return! decryptedOverviewData |> OPData.getPlainText
  }

let bandfilename = "testdata\\onepassword_data\\default\\band_0.js"
let password = "freddy"

let makeBandFileJSON =
  let startMarker = "ld({"
  let endMarker = "});"

  String.makeJSON startMarker endMarker

type BandFileJson = FSharp.Data.JsonProvider<"""{"FOO":{"uuid":"FOO","category":"099","o":"FOO","hmac":"FOO","updated":1386214150,"trashed":true,"k":"FOO","d":"FOO","created":1386214097,"tx":1386214431},"BAR":{"category":"004","k":"BAR","updated":1325483949,"tx":1373753421,"d":"BAR","hmac":"BAR","created":1325483949,"uuid":"BAR","o":"BAR"}}""">

let parseBandFileJSON (json: string) =
  try
    Ok (BandFileJson.Parse json)
  with
  | e -> JSONParserError e.Message |> ParserError |> Error

let readBandFile password bandfilename = 
  let contents =
    trial {
      let! profile = Profile.read "testdata\\onepassword_data\\default\\profile.js"
      let! profile = profile |> Profile.decrypt password
      let! overviewKey = profile |> Profile.getDecryptedOverviewKey
      let! content = File.read bandfilename
      let! json = content |> makeBandFileJSON
      let! json = json |> parseBandFileJSON
      let values = [ for prop in json.JsonValue.Properties -> prop |> snd |> (fun v -> v?o.AsString()) |> ByteArray.fromBase64 ]
      let overviews = seq { 
        for o in values do
          match o |> getOverview overviewKey with
          | Ok overview -> yield overview
          | _ -> ()
      }
      return overviews |> Seq.toList
    }   
  match contents with
  | Ok contents -> contents
  | _ -> [ ]

type OverviewJSON = FSharp.Data.JsonProvider<""" 
[
  {"ps":0},
  {"title":"Personal","ainfo":"Wendy Appleseed","tags":["Sample","Personal"],"ps":0},
  {"title":"Hulu","URLs":[{"u":"http://www.hulu.com/"}],"ainfo":"wendy@appleseed.com","url":"http://www.hulu.com/","tags":["Sample"],"ps":66},
  {"title":"Wendy's driver's license","ps":0,"ainfo":"D6101-40706-60905"},
  {"title":"Orders","ainfo":"10.0.1.50","tags":["Sample"],"ps":0},{"URLs":[{"u":"https://secure.skype.com/account/login?message=login_required"}],"tags":["Sample"],"title":"Skype","url":"https://secure.skype.com/account/login?message=login_required","ainfo":"WendyAppleseed","ps":78},
  {"title":"YouTube","URLs":[{"u":"http://www.youtube.com/login?next=/index"}],"ainfo":"wendy@appleseed.com","url":"http://www.youtube.com/login?next=/index","tags":["Sample"],"ps":78},
  {"title":"example.com","ps":0,"ainfo":"wappleseed"},
  {"title":"Dropbox","URLs":[{"u":"https://www.getdropbox.com/"}],"ainfo":"wendy@appleseed.com","url":"https://www.getdropbox.com/","tags":["Sample"],"ps":78},
  {"title":"Company's FTP","URLs":[{"u":"ftp://ftp.dreamhost.com"}],"ainfo":"admin","url":"ftp://ftp.dreamhost.com","tags":["Sample"],"ps":60},
  {"title":"Tumblr","URLs":[{"u":"http://www.tumblr.com/login"}],"ainfo":"wendy@appleseed.com","url":"http://www.tumblr.com/login","tags":["Sample"],"ps":48},
  {"title":"Social Security","ps":0,"ainfo":"Wendy Appleseed"},
  {"title":"Last.fm","URLs":[{"u":"https://www.last.fm/login"}],"ainfo":"WendyAppleseed","url":"https://www.last.fm/login","tags":["Sample"],"ps":72},
  {"title":"Tim Hortons","ps":0,"ainfo":"Tim Hortens"},
  {"title":"Snipe Hunting License","ps":0,"ainfo":"Wendy Appleseed"},
  {"title":"A note to Trash","ainfo":"Let’s create a note that we will throw in the trash but not expunge.","ps":0},
  {"title":"CapitalOne MasterCard ***3456","ainfo":"1234 *********** 3456","tags":["Sample"],"ps":0},
  {"title":"What is a Secure Note?","ainfo":"","tags":["Sample"],"ps":0},
  {"title":"The Unofficial Apple Weblog","URLs":[{"u":"http://www.tuaw.com"}],"ainfo":"WendyAppleseed","url":"http://www.tuaw.com","tags":["Sample"],"ps":78},
  {"title":"Wendy's passport","ps":0,"ainfo":"ZZ200000"},
  {"title":"Chase VISA ***4356","ainfo":"1234 *********** 4356","tags":["Sample"],"ps":0},
  {"title":"Bank of America","URLs":[{"u":"https://www.bankofamerica.com/"}],"ainfo":"WendyAppleseed","url":"https://www.bankofamerica.com/","tags":["Sample","Personal"],"ps":66},
  {"title":"A note with some attachments","ps":0,"ainfo":"This note has two attachments."},
  {"title":"1Password","ainfo":"3.0","tags":["Sample"],"ps":0},
  {"title":"TextExpander","ainfo":"1.3","tags":["Sample"],"ps":0},
  {"title":"Business","ainfo":"Wendy Appleseed","tags":["Business","Sample"],"ps":0},
  {"title":"MobileMe","URLs":[{"u":"https://www.icloud.com/"}],"ainfo":"wendy.appleseed@me.com","url":"https://www.icloud.com/","tags":["Sample"],"ps":66},
  {"title":"Email Account","ps":0,"ainfo":"wendy.appleseed@me.com"},
  {"title":"Johnny Appleseed Society","ps":0,"ainfo":"Wendy Appleseed"}
] """>

let vaultDir = "testdata\\onepassword_data\\default"
let readOverviews password vaultDir =
  [ for i in 0 .. 15 -> (sprintf "%x" i).ToUpper() |> sprintf "%s\\band_%s.js" vaultDir ]
  |> List.collect (readBandFile password)
  |> List.fold (sprintf "%s,%s") ""
  |> fun s -> s.Trim([| ',' |])
  |> sprintf "[%s]"

let encryptedOverview = "b3BkYXRhMDEIAAAAAAAAAMQDerODSnrtEVkZHp0tO5qokNWe+77F7yjsHcCvBEdxYL9DPSUuPV4FDv1F4E3VXWoY4BBYZrm8G3IUekJhL3E="

trial {
  let! profile = Profile.read "testdata\\onepassword_data\\default\\profile.js"
  let encryptedOverview = encryptedOverview |> System.Convert.FromBase64String
  return! getOverview password profile encryptedOverview
}

let encryptedItemKey = "6MnmUT7fNchO0lIDNYGITOAO0cubw8Qsad1dEBZFCUSXrUOR7IkFUwddSA8QBJTH7P7iJytKB00KclFRNR/zf+AC+VD6aCQiznj1zx8uKoxG9Wv1v4YsnH95NbC8UvRxCn+XA+6WRZII2kWN10IN9w=="

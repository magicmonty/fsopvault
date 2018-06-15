namespace Pagansoft.OPVault

[<RequireQualifiedAccess>]
module Crypto =
  let KeySizeInBits = 256
  let KeySizeInBytes = KeySizeInBits / 8
  let HMACSizeInBytes = KeySizeInBytes
  let IVSizeInBytes = 16
  let PaddedBlockSize = 16

  let calcPaddingSize l = PaddedBlockSize - (l % PaddedBlockSize)
  let initArrayOfLength l = [| for _ in 1 .. l -> 0uy |]
module SHA1 (sha1, Digest (..)) where

import Data.Bits
import qualified Data.ByteString.Lazy as B
import Data.List (unfoldr)
import Data.Word (Word32, Word8)
import GHC.Int (Int64)
import Text.Printf (printf)

---- Digest data ---------------------------------------------------------------

data Block
  = Block
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
      Word32
  deriving (Eq)

data Digest = Digest Word32 Word32 Word32 Word32 Word32 deriving (Eq)

instance Show Digest where
  show (Digest w0 w1 w2 w3 w4) = printf "%08x%08x%08x%08x%08x" w0 w1 w2 w3 w4

instance Num Digest where
  abs = id
  signum 0 = 0
  signum _ = 1
  (+) (Digest a0 b0 c0 d0 e0) (Digest a1 b1 c1 d1 e1) =
    Digest (a0 + a1) (b0 + b1) (c0 + c1) (d0 + d1) (e0 + e1)
  (*) (Digest a0 b0 c0 d0 e0) (Digest a1 b1 c1 d1 e1) =
    Digest (a0 * a1) (b0 * b1) (c0 * c1) (d0 * d1) (e0 * e1)
  (-) (Digest a0 b0 c0 d0 e0) (Digest a1 b1 c1 d1 e1) =
    Digest (a0 - a1) (b0 - b1) (c0 - c1) (d0 - d1) (e0 - e1)
  fromInteger i = Digest w0 w1 w2 w3 w4
    where
      w0 = fromInteger $ shiftR i 128
      w1 = fromInteger $ shiftR i 96
      w2 = fromInteger $ shiftR i 64
      w3 = fromInteger $ shiftR i 32
      w4 = fromInteger $ shiftR i 0

---- SHA-1 sub functions for hashing -------------------------------------------

ch :: Word32 -> Word32 -> Word32 -> Word32
ch x y z = xor (x .&. y) $ complement x .&. z

parity :: Word32 -> Word32 -> Word32 -> Word32
parity x y z = xor x $ xor y z

maj :: Word32 -> Word32 -> Word32 -> Word32
maj x y z = parity (x .&. y) (x .&. z) (y .&. z)

---- Functions for padding the input message -----------------------------------

makeBlocks :: B.ByteString -> [Block]
makeBlocks s = map makeBlock $ groupsOfB 64 $ pad s

makeBlock :: B.ByteString -> Block
makeBlock s = case map packWords $ groupsOf 4 $ B.unpack s of
  [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] ->
    Block w0 w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 w13 w14 w15
  x -> error $ "Expected 16 Word32s, got " ++ show (length x) ++ " instead."

packWords :: [Word8] -> Word32
packWords ws = sum $ zipWith shiftL (map fromIntegral ws) [24, 16 .. 0]

pad :: B.ByteString -> B.ByteString
pad u = B.append u $ B.append lPad rPad
  where
    padLen = (55 - B.length u) `mod` 64
    lPad = B.cons 0x80 $ B.replicate padLen 0x00
    rPad = B.pack $ map (fromIntegral . shiftR (B.length u * 8)) [56, 48 .. 0]

---- Helper Functions ----------------------------------------------------------

groupsOf :: Int -> [a] -> [[a]]
groupsOf n = takeWhile (not . null) . unfoldr (Just . splitAt n)

groupsOfB :: Int64 -> B.ByteString -> [B.ByteString]
groupsOfB n = takeWhile (not . B.null) . unfoldr (Just . B.splitAt n)

---- Generate W, the message schedule ------------------------------------------

msgSchedule :: Block -> [Word32]
msgSchedule (Block w0 w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 w13 w14 w15) =
  reverse . last . take 80 . iterate appendBlk $ reverse b
  where
    appendBlk x = newBlk x : x
    newBlk blks = rotateL (foldl (\w -> xor w . (blks !!)) 0 [2, 7, 13, 15]) 1
    b = [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15]

---- Hash all of the blocks in a message ---------------------------------------

sha1 :: B.ByteString -> Digest
sha1 = hashBlocks . makeBlocks

hashBlocks :: [Block] -> Digest
hashBlocks = foldl hashBlock initHash
  where
    initHash = Digest 0x67452301 0xefcdab89 0x98badcfe 0x10325476 0xc3d2e1f0

hashBlock :: Digest -> Block -> Digest
hashBlock d blk = d + foldl (hashBlockGen $ msgSchedule blk) d [0 .. 79]

hashBlockGen :: [Word32] -> Digest -> Int -> Digest
hashBlockGen w (Digest a b c d e) i = Digest t a (rotateL b 30) c d
  where
    t = rotateL a 5 + (ft !! ti) b c d + e + (kt !! ti) + (w !! i)
    ti = i `div` 20
    ft = [ch, parity, maj, parity]
    kt = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]

module SHA1 (sha1, showDigest, Digest) where

import Data.Bits
import Data.List (unfoldr)
import Data.Word (Word32, Word8)
import Text.Printf (printf)

sha1 :: [Word8] -> Digest
sha1 w = hashBlocks $ makeBlocks w

---- Digest data type and supporting functions -------------------------------------------------------------------------

data Digest = Digest Word32 Word32 Word32 Word32 Word32 deriving (Show, Eq)

showDigest :: Digest -> String
showDigest (Digest w0 w1 w2 w3 w4) = printf "%08x%08x%08x%08x%08x" w0 w1 w2 w3 w4

addDigests :: Digest -> Digest -> Digest
addDigests (Digest a0 b0 c0 d0 e0) (Digest a1 b1 c1 d1 e1) =
  Digest (a0 + a1) (b0 + b1) (c0 + c1) (d0 + d1) (e0 + e1)

---- SHA-1 constants ---------------------------------------------------------------------------------------------------

initHash :: Digest
initHash = Digest 0x67452301 0xefcdab89 0x98badcfe 0x10325476 0xc3d2e1f0

kt :: [Word32]
kt = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6] :: [Word32]

ft :: [Word32 -> Word32 -> Word32 -> Word32]
ft = [ch, parity, maj, parity]

---- SHA-1 sub functions for hashing -----------------------------------------------------------------------------------

ch :: Word32 -> Word32 -> Word32 -> Word32
ch x y z = xor (x .&. y) (complement x .&. z)

parity :: Word32 -> Word32 -> Word32 -> Word32
parity x y z = foldl xor 0 [x, y, z]

maj :: Word32 -> Word32 -> Word32 -> Word32
maj x y z = foldl xor 0 [x .&. y, x .&. z, y .&. z]

rotl :: Int -> Word32 -> Word32
rotl n x = shiftL x n .|. shiftR x (32 - n)

---- Functions for padding the input message ---------------------------------------------------------------------------

makeBlocks :: [Word8] -> [[Word32]]
makeBlocks w = groupsOf 16 . map packWord32 . groupsOf 32 . pad $ wordsToBits w

pad :: [Bool] -> [Bool]
pad u = u ++ [True] ++ paddingBits ++ msgLenEnc
  where
    paddingBits = replicate ((447 - length u) `mod` 512) False
    msgLenEnc = [testBit (length u) b | b <- reverse [0 .. 63]]

---- Helper Functions --------------------------------------------------------------------------------------------------

groupsOf :: Int -> [a] -> [[a]]
groupsOf n = takeWhile (not . null) . unfoldr (Just . splitAt n)

wordsToBits :: [Word8] -> [Bool]
wordsToBits = concatMap (\x -> [testBit x b | b <- reverse [0 .. 7]])

packWord32 :: [Bool] -> Word32
packWord32 [] = 0
packWord32 xs = foldl setBit 0 (map snd $ filter fst $ zip xs (reverse [0 .. 31]))

---- Recursively Generate W, the message schedule ----------------------------------------------------------------------

msgSchedule :: [Word32] -> [Word32]
msgSchedule m
  | length m == 80 = m
  | otherwise = msgSchedule (m ++ [rotl 1 foldedSch])
  where
    newSch = map (\x -> m !! (length m - x)) [3, 8, 14, 16]
    foldedSch = foldl xor 0 newSch

---- Hash all of the blocks in a message -------------------------------------------------------------------------------

hashBlocks :: [[Word32]] -> Digest
hashBlocks = foldl hashBlock initHash

hashBlock :: Digest -> [Word32] -> Digest
hashBlock h blk = addDigests h newDigest
  where
    newDigest = hashBlockRec h (msgSchedule blk) 0

hashBlockRec :: Digest -> [Word32] -> Int -> Digest
hashBlockRec digest _ 80 = digest
hashBlockRec (Digest a b c d e) w depth = hashBlockRec newDigest w (depth + 1)
  where
    t = rotl 5 a + (ft !! tIndex) b c d + e + (kt !! tIndex) + (w !! depth)
    tIndex = depth `div` 20
    newDigest = Digest t a (rotl 30 b) c d

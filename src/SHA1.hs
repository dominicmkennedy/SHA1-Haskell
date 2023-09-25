module SHA1 (sha1, Digest (..)) where

import Data.Bits
import Data.List (unfoldr)
import Data.Word (Word32, Word8)
import Text.Printf (printf)

---- Digest data ---------------------------------------------------------------

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

rotl :: Int -> Word32 -> Word32
rotl n x = shiftL x n .|. shiftR x (32 - n)

---- Functions for padding the input message -----------------------------------

makeBlocks :: [Word8] -> [[Word32]]
makeBlocks = groupsOf 16 . map packWord32 . groupsOf 32 . pad . wordsToBits

pad :: [Bool] -> [Bool]
pad u = u ++ True : paddingBits ++ msgLenEnc
  where
    paddingBits = replicate ((447 - length u) `mod` 512) False
    msgLenEnc = [testBit (length u) b | b <- reverse [0 .. 63]]

---- Helper Functions ----------------------------------------------------------

groupsOf :: Int -> [a] -> [[a]]
groupsOf n = takeWhile (not . null) . unfoldr (Just . splitAt n)

wordsToBits :: [Word8] -> [Bool]
wordsToBits = concatMap (\x -> [testBit x b | b <- reverse [0 .. 7]])

packWord32 :: [Bool] -> Word32
packWord32 [] = 0
packWord32 xs = foldl setBit 0 $ map snd $ filter fst $ zip xs [31, 30 .. 0]

---- Generate W, the message schedule ------------------------------------------

msgSchedule :: [Word32] -> [Word32]
msgSchedule = reverse . last . take 80 . iterate appendBlk . reverse
  where
    appendBlk x = newBlk x : x
    newBlk blks = rotl 1 $ foldl (\w -> xor w . (blks !!)) 0 [2, 7, 13, 15]

---- Hash all of the blocks in a message ---------------------------------------

sha1 :: [Word8] -> Digest
sha1 = hashBlocks . makeBlocks

hashBlocks :: [[Word32]] -> Digest
hashBlocks = foldl hashBlock initHash
  where
    initHash = Digest 0x67452301 0xefcdab89 0x98badcfe 0x10325476 0xc3d2e1f0

hashBlock :: Digest -> [Word32] -> Digest
hashBlock d blk = d + foldl (hashBlockGen $ msgSchedule blk) d [0 .. 79]

hashBlockGen :: [Word32] -> Digest -> Int -> Digest
hashBlockGen w (Digest a b c d e) i = Digest t a (rotl 30 b) c d
  where
    t = rotl 5 a + (ft !! ti) b c d + e + (kt !! ti) + (w !! i)
    ti = i `div` 20
    ft = [ch, parity, maj, parity]
    kt = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]

{-# LANGUAGE OverloadedStrings #-}
module Main where

import Control.Applicative ((<$>))
import Control.Concurrent.MVar
import Control.Monad       (void)
import Data.ByteString.Char8 (pack, unpack, take, drop, replicate)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as Hex
import qualified Data.ByteString.Base64 as B64
import qualified Data.Serialize         as S
import Prelude hiding (take, drop, replicate)
import System.Environment
import Network.Socket
import qualified Network.Socket.ByteString as NBS

import Crypto.Hash.BLAKE2.BLAKE2s
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Hash.BLAKE2s
import Crypto.Noise.Types

import Data.Time.TAI64

w :: PublicKey Curve25519
  -> Plaintext
  -> Socket
  -> SockAddr
  -> ByteString
  -> IO ()
w theirPub (Plaintext myPSK) sock addr msg = do
  let x      = "\x01\x00\x00" `mappend` msg
      mac    = hash 16 myPSK (sbToBS' (curvePubToBytes theirPub) `mappend` sbToBS' x)
  void $ NBS.sendTo sock (x `mappend` mac `mappend` replicate 16 '\0') addr

r :: MVar ByteString -> Socket -> IO ByteString
r smv sock = do
  (r, _) <- NBS.recvFrom sock 1024
  putMVar smv $ (take 2 . drop 1) r
  return . take 48 . drop 5 $ r

payload :: IO Plaintext
payload = do
  tai64n <- getCurrentTAI64N
  return . Plaintext . bsToSB' $ S.encode tai64n

main :: IO ()
main = do
  let ip = "demo.wireguard.io"
  let port = "12913"
  let mykey = "WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo="
  let serverkey = "qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM="
  let psk = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
  addrInfo <- head <$> getAddrInfo Nothing (Just ip) (Just port)
  sock     <- socket (addrFamily addrInfo) Datagram defaultProtocol

  let addr       = addrAddress addrInfo
      mykey'     = curveBytesToPair  . bsToSB' . either undefined id . B64.decode . pack $ mykey     :: KeyPair Curve25519
      serverkey' = curveBytesToPub   . bsToSB' . either undefined id . B64.decode . pack $ serverkey :: PublicKey Curve25519
      psk'       = Plaintext . bsToSB' . either undefined id . B64.decode . pack $ psk
      hs         = handshakeState $ HandshakeStateParams
                   noiseIK
                   "WireGuard v0 zx2c4 Jason@zx2c4.com"
                   (Just psk')
                   (Just mykey')
                   Nothing
                   (Just serverkey')
                   Nothing
                   True :: HandshakeState ChaChaPoly1305 Curve25519 BLAKE2s

  senderindexmv <- newEmptyMVar
  let hc = HandshakeCallbacks (w serverkey' psk' sock addr) (r senderindexmv sock) (\_ -> return ()) payload
  (encryption, decryption) <- runHandshake hs hc

  let (keepAlive, encryption') = encryptPayload "" encryption
  senderindex <- takeMVar senderindexmv
  void $ NBS.sendTo sock ("\x04" `mappend` senderindex `mappend` replicate 8 '\0' `mappend` keepAlive) addr

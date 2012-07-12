{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Network.BSD
import Network.Socket
import Network.TLS
import Network.TLS.Extra
import System.IO
import qualified Crypto.Random.AESCtr as RNG
import qualified Data.ByteString.Lazy.Char8 as LC
import Control.Exception
import System.Environment
import Prelude hiding (catch)
import Control.Monad
import System.Exit

import Data.IORef

validateCert = False
sendClientCert = True
debug = True

ciphers :: [Cipher]
ciphers =
	[ cipher_AES128_SHA1
	, cipher_AES256_SHA1
	, cipher_RC4_128_MD5
	, cipher_RC4_128_SHA1
	]

runTLS params hostname portNumber f = do
	rng  <- RNG.makeSystem
	he   <- getHostByName hostname
	sock <- socket AF_INET Stream defaultProtocol
	let sockaddr = SockAddrInet portNumber (head $ hostAddresses he)
	catch (connect sock sockaddr)
	      (\(e :: SomeException) -> sClose sock >> error ("cannot open socket " ++ show sockaddr ++ " " ++ show e))
	dsth <- socketToHandle sock ReadWriteMode
	ctx <- contextNewOnHandle dsth params rng
	_ <- f ctx
	hClose dsth

getDefaultParams sStorage session certs = defaultParamsClient
	{ pConnectVersion    = TLS10
	, pAllowedVersions   = [TLS10,TLS11,TLS12]
	, pCiphers           = ciphers
	, pCertificates      = certs
	, pLogging           = logging
	, onCertificatesRecv = crecv
        , pClientCertParamsClient = Just (ClientCertParamsClient {
                                             onCertificateRequest = creq
                                             })
	, onSessionEstablished = \s d -> writeIORef sStorage (s,d)
	, sessionResumeWith  = session
	}
	where
		logging = if not debug then defaultLogging else defaultLogging
			{ loggingPacketSent = putStrLn . ("debug: >> " ++)
			, loggingPacketRecv = putStrLn . ("debug: << " ++)
			}
		crecv = if validateCert then certificateVerifyChain else (\_ -> return CertificateUsageAccept)
                creq = if sendClientCert then (\ _ -> return certs) else (\ _ -> return [])


main = do
	sStorage <- newIORef undefined
	args     <- getArgs
        when (length args /= 2 && length args /= 4) $ do
          putStrLn $ "usage: tls-simpleclient HOST PORT [CERTIFICATEFILE KEYFILE]"
          exitWith (ExitFailure 1)
	let hostname = args !! 0
	let port = read (args !! 1) :: Int
        certs <- if sendClientCert && length args == 4
                 then do
                   cert    <- fileReadCertificate $ args !! 2
                   pk      <- fileReadPrivateKey $ args !! 3
                   return [(cert, Just pk)]
                 else return []
	runTLS (getDefaultParams sStorage Nothing certs) hostname (fromIntegral port) $ \ctx -> do
		handshake ctx
		sendData ctx $ LC.pack "GET / HTTP/1.0\r\n\r\n"
		d <- recvData' ctx
		bye ctx
		LC.putStrLn d
		return ()
{-
	session <- readIORef sStorage
	runTLS (getDefaultParams sStorage $ Just session) hostname port $ \ctx -> do
		handshake ctx
		sendData ctx $ LC.pack "GET / HTTP/1.0\r\n\r\n"
		d <- recvData ctx
		bye ctx
		LC.putStrLn d
		return ()
-}

#[
Copyright (C) 2021 cozyGalvinism

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
]#
import system
import argparse
import os
import strutils
import sequtils
import strformat

proc readFiles(filePaths: seq[string]): seq[string] =
  var fileContents: seq[string] = @[]
  for fp in filePaths:
    fileContents.add(readFile(fp))
  return fileContents

proc buildChain(cert: string, ca: string, intermediates: seq[string]) {.discardable.} =
  var chainContents: string = ""

  chainContents = cert & "\p"
  for intermediate in intermediates:
    chainContents = chainContents & intermediate & "\p"
  chainContents = chainContents & ca & "\p"

  try:
    discard existsOrCreateDir("out")
    writeFile("out/chain.crt", chainContents)
  except IOError as _:
    stderr.writeLine(getCurrentExceptionMsg())
    quit(1)

proc installedBefore(wwsPath: string): bool =
  var wwsIniPath: string = joinPath(wwsPath, "wws.ini.beforewwec")
  return fileExists(wwsIniPath)

proc installFirstTime(wwsPath: string, cert: string, ca: string, privkey: string, password: string) {.discardable.} =
  var wwsEasyCertPath: string = joinPath(wwsPath, "WWEasyCert")
  var wwsIniPath: string = joinPath(wwsPath, "wws.ini")
  var wwsIniBeforePath: string = joinPath(wwsPath, "wws.ini.beforewwec")
  var easyCertCert: string = joinPath(wwsEasyCertPath, "cert.crt")
  var easyCertCa: string = joinPath(wwsEasyCertPath, "ca.crt")
  var easyCertPrivkey: string = joinPath(wwsEasyCertPath, "private.key")
  var easyCertChain: string = joinPath(wwsEasyCertPath, "chain.crt")

  try:
    discard existsOrCreateDir(joinPath(wwsPath, "WWEasyCert"))
    copyFile(cert, easyCertCert)
    copyFile(ca, easyCertCa)
    copyFile(privkey, easyCertPrivkey)
    copyFile(joinPath("out", "chain.crt"), easyCertChain)
    copyFile(wwsIniPath, wwsIniBeforePath)

    var iniLines: seq[string] = splitLines(readFile(wwsIniPath))
    iniLines = concat(@[
      "# MANAGED BY WWEasyCert",
      "# Please don't touch this section of this file",
      "# If you need to make edits to the file, please apply them to both wws.ini and wws.ini.beforewwec",
      fmt"BWWSSL_CA_ZERTIFIKAT={easyCertCa}",
      fmt"BWWSSL_ZERTIFIKAT={easyCertCert}",
      fmt"BWWSSL_PASSWORD4PRIVKEY={password}",
      fmt"BWWSSL_PRIVATEKEY={easyCertPrivkey}",
      fmt"BWWSSL_USE_CHAIN_ZERTIFIKAT=J",
      fmt"BWWSSL_CHAIN_ZERTIFIKAT={easyCertChain}",
      ""
    ], iniLines)
    var iniFile: File = open(wwsIniPath, FileMode.fmWrite)
    var iniContents: string = iniLines.join("\p")
    iniFile.write(iniContents)
  except IOError as _:
    stderr.writeLine(getCurrentExceptionMsg())
    quit(1)

proc installAgain(wwsPath: string, cert: string, ca: string, privkey: string, password: string) {.discardable} =
  var wwsIniPath: string = joinPath(wwsPath, "wws.ini")
  var wwsIniBeforePath: string = joinPath(wwsPath, "wws.ini.beforewwec")
  copyFile(wwsIniBeforePath, wwsIniPath)
  installFirstTime(wwsPath, cert, ca, privkey, password)

const PARSER = newParser("WWEasyCert"):
  help("""Easy to use WEBWARE Certificate Installer
  
WWEasyCert Copyright (C) 2021 cozyGalvinism
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.""")
  option("-p", "--password", "Password for the private key")
  option("-i", "--install", "Path to WWS for installing the certificate files")
  arg("cert", help = "Path to certificate file")
  arg("privkey", help = "Path to private key file")
  arg("ca", help = "Path to CA certificate file")
  arg("intermediates", help = "Paths to one or more intermediate certificates", nargs = -1)
  run:
    echo """WWEasyCert Copyright (C) 2021 cozyGalvinism
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions."""
    let 
      cert: string = opts.cert
      privkey: string = opts.privkey
      ca: string = opts.ca
      intermediates: seq[string] = opts.intermediates
      password: string = opts.password
      install: string = opts.install
      doInstall: bool = not isEmptyOrWhitespace(opts.install)

    try:
      let
        certContent: string = readFile(cert)
        privkeyContent: string = readFile(privkey)
        caContent: string = readFile(ca)
        intermediatesContent: seq[string] = readFiles(intermediates)

      echo "Building certificate chain..."
      buildChain(certContent, caContent, intermediatesContent)
      if doInstall:
        if installedBefore(install):
          echo "WWEasyCert has been running before, refreshing..."
          installAgain(install, cert, ca, privkey, password)
        else:
          echo "Installing certificates for the first time, please wait..."
          installFirstTime(install, cert, ca, privkey, password)
    except IOError as _:
      stderr.writeLine(getCurrentExceptionMsg())
      quit(1)

when isMainModule:
  try:
    PARSER.run(commandLineParams())
  except UsageError as _:
    stderr.writeLine(getCurrentExceptionMsg())
    quit(1)
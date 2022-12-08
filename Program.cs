using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace EbayHttpSignature
{
    internal class Program
    {
        private static string[] signatureParameters = new string[] { "content-digest", "x-ebay-signature-key", "@method", "@path", "@authority" };
        private static string signatureInput = string.Empty;

        static void Main(string[] args)
        {
            //var token = "enter token here";
            var jwe = "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiSXh2dVRMb0FLS0hlS0Zoa3BxQ05CUSIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiaFd3YjNoczk2QzEyOTNucCJ9.2o02pR9SoTF4g_5qRXZm6tF4H52TarilIAKxoVUqjd8.3qaF0KJN-rFHHm_P.AMUAe9PPduew09mANIZ-O_68CCuv6EIx096rm9WyLZnYz5N1WFDQ3jP0RBkbaOtQZHImMSPXIHVaB96RWshLuJsUgCKmTAwkPVCZv3zhLxZVxMXtPUuJ-ppVmPIv0NzznWCOU5Kvb9Xux7ZtnlvLXgwOFEix-BaWNomUAazbsrUCbrp514GIea3butbyxXLNi6R9TJUNh8V2uan-optT1MMyS7eMQnVGL5rYBULk.9K5ucUqAu0DqkkhgubsHHw";
            var privateKey = "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF";

            var client = new RestClient("http://172.17.0.2:8080"); //new RestClient("https://api.sandbox.ebay.com");
            var request = new RestRequest("verifysignature", Method.Post); //new RestRequest("/sell/fulfillment/v1/order/14-00032-43825/issue_refund", Method.Post);
            var uri = client.BuildUri(request);
            var message = "{\"hello\": \"world\"}";
            var contentHash = ComputeContentHash(message);

            request.AddStringBody(message, DataFormat.Json);
            request.AddHeader("x-ebay-signature-key", $"{jwe}");
            request.AddHeader("Content-Digest", $"sha-256=:{contentHash}:");
            request.AddHeader("Signature", $"sig1=:{SignSignature(privateKey, request, uri)}:");
            request.AddHeader("Signature-Input", $"sig1={signatureInput}");
            request.AddHeader("x-ebay-enforce-signature", "true");
            //request.AddHeader("Authorization", $"Bearer {token}");
            var result = client.Execute(request);
            Console.WriteLine(result.StatusCode);
            Console.WriteLine(result.Content);
        }

        static string SignSignature(string privateKey, RestRequest request, Uri uri)
        {
            var signature = GetSignature(request, uri);
            Console.WriteLine(signature);
            var signatureBase = Encoding.UTF8.GetBytes(signature);
            var key = PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            var signer = new Ed25519Signer();
            signer.Init(true, key);
            signer.BlockUpdate(signatureBase, 0, signatureBase.Length);
            var sig = Convert.ToBase64String(signer.GenerateSignature(), Base64FormattingOptions.None);
            return sig;
        }

        static Org.BouncyCastle.Crypto.AsymmetricKeyParameter ReadAsymmetricKeyParameter(string pemFilename)
        {
            var fileStream = System.IO.File.OpenText(pemFilename);
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(fileStream);
            var KeyParameter = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)pemReader.ReadObject();
            return KeyParameter;
        }

        static string GetSignature(RestRequest request, Uri uri)
        {
            var sb = new StringBuilder();
            var requestHeaders = request.Parameters.Where(x => x.Type == ParameterType.HttpHeader);
            foreach (var param in signatureParameters)
            {
                sb.Append($"\"{param.ToLower()}\": ");
                if (param.StartsWith("@"))
                {
                    switch (param.ToLower())
                    {
                        case "@method":
                            sb.Append(request.Method.ToString().ToUpper());
                            break;
                        case "@path":
                            sb.Append(uri.AbsolutePath);
                            break;
                        case "@authority":
                            sb.Append(uri.Authority);
                            break;
                    }
                }
                else
                {
                    var value = requestHeaders.FirstOrDefault(x => x?.Name?.ToLower() == param.ToLower());
                    if (value is null)
                        throw new Exception("Header " + param + " not included in message");
                    sb.Append(value.Value);
                }
                sb.AppendLine();
            }

            sb.Append("\"@signature-params\": ");
            signatureInput = GetSignatureInput();
            sb.Append(signatureInput);

            return sb.ToString();
        }

        static string GetSignatureInput()
        {
            var sb = new StringBuilder($"(");
            foreach (var param in signatureParameters)
            {
                if (sb.ToString().EndsWith("("))
                    sb.Append($"\"{param}\"");
                else
                    sb.Append($" \"{param}\"");
            }
            sb.Append($");created={DateTimeOffset.Now.ToUnixTimeSeconds()}");

            return sb.ToString();
        }

        static string ComputeContentHash(string content)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
                return Convert.ToBase64String(hashedBytes);
            }
        }
    }
}
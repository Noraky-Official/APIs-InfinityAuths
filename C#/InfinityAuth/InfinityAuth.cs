using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace InfinityAuth
{
    public class api
    {
        public string name, ownerid, secret, version;
        public Response response;
        public UserInfo user_data;
        private string sessionid;
        private bool initialized = false;
        private const string ApiUrl = "https://infinityauth.shardweb.app/api/InfinityAuth/";

        public api() { }

        public api(string name, string ownerid, string secret, string version)
        {
            this.name = name;
            this.ownerid = ownerid;
            this.secret = secret;
            this.version = version;
        }

        public void setup(string name, string ownerid, string secret, string version)
        {
            this.name = name;
            this.ownerid = ownerid;
            this.secret = secret;
            this.version = version;
            init();
        }

        public void setup() => init();

        public void init()
        {
            this.response = SendRequest(new NameValueCollection
            {
                ["type"] = "init",
                ["ver"] = version
            });

            if (this.response.success)
            {
                sessionid = this.response.sessionid;
                initialized = true;
            }
        }

        public void login(string user, string pass)
        {
            this.response = SendRequest(new NameValueCollection
            {
                ["type"] = "login",
                ["username"] = user,
                ["pass"] = pass,
                ["hwid"] = GetHwid(),
                ["sessionid"] = sessionid
            });
            if (this.response.success && this.response.info != null)
                this.user_data = this.response.info;
        }

        public void register(string user, string pass, string key)
        {
            this.response = SendRequest(new NameValueCollection
            {
                ["type"] = "register",
                ["username"] = user,
                ["pass"] = pass,
                ["key"] = key,
                ["hwid"] = GetHwid()
            });
        }

        public void license(string key)
        {
            this.response = SendRequest(new NameValueCollection
            {
                ["type"] = "license",
                ["key"] = key,
                ["hwid"] = GetHwid()
            });
            if (this.response.success && this.response.info != null)
                this.user_data = this.response.info;
        }

        public string GetVar(string varName)
        {
            var res = SendRequest(new NameValueCollection
            {
                ["type"] = "var",
                ["var"] = varName,
                ["sessionid"] = sessionid
            });
            return res.success ? res.value : null;
        }

        public void TriggerWebhook(string webhookName, string data = "")
        {
             SendRequest(new NameValueCollection
            {
                ["type"] = "webhook",
                ["webhook"] = webhookName,
                ["sessionid"] = sessionid,
                ["data"] = data
            });
        }

        // --- Helpers ---

        private string GetHwid()
        {
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
                ManagementObjectCollection collection = searcher.Get();
                foreach (ManagementObject obj in collection)
                {
                    return obj["SerialNumber"].ToString();
                }
            } catch { }
            return "unknown-hwid";
        }

        private void MessageBox(string text) => System.Windows.Forms.MessageBox.Show(text, "InfinityAuth V2");

        // --- Core: Encrypted Request ---

        private class TimeoutWebClient : WebClient
        {
            protected override WebRequest GetWebRequest(Uri uri)
            {
                WebRequest w = base.GetWebRequest(uri);
                w.Timeout = 15000; // Timeout de 15 segundos (Evita crashar UI do Loader)
                return w;
            }
        }

        private Response SendRequest(NameValueCollection data)
        {
            using (var client = new TimeoutWebClient())
            {
                var postData = new Dictionary<string, string>();
                foreach (string key in data.AllKeys) postData[key] = data[key];
                
                string json = JsonConvert.SerializeObject(postData);
                string encryptedBody = Encrypt(json, secret);

                var reqPayload = new NameValueCollection
                {
                    ["name"] = name,
                    ["ownerid"] = ownerid,
                    ["enc"] = "1",
                    ["data"] = encryptedBody
                };

                try
                {
                    byte[] responseBytes = client.UploadValues(ApiUrl, reqPayload);
                    string rawResponse = Encoding.Default.GetString(responseBytes);

                    var wrapper = JsonConvert.DeserializeObject<Response>(rawResponse);
                    if (wrapper.enc == "1" && !string.IsNullOrEmpty(wrapper.data))
                    {
                        string decrypted = Decrypt(wrapper.data, secret);
                        return JsonConvert.DeserializeObject<Response>(decrypted);
                    }
                    return wrapper;
                }
                catch (Exception e)
                {
                    return new Response { success = false, message = "Erro de conexão: " + e.Message };
                }
            }
        }

        private string Encrypt(string text, string keyStr)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(keyStr));
                aes.Key = key;
                aes.GenerateIV(); // Gerar IV Dinâmico e aleatório
                aes.Mode = CipherMode.CBC;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs)) sw.Write(text);
                        // Retorna [IV Hex] + [Cipher Hex]
                        return ToHexString(aes.IV) + ToHexString(ms.ToArray());
                    }
                }
            }
        }

        private string Decrypt(string hexData, string keyStr)
        {
            if (hexData.Length < 32) return "{}"; // Evita exceptions

            string ivHex = hexData.Substring(0, 32);
            string cipherHex = hexData.Substring(32);

            byte[] iv = FromHexString(ivHex);
            byte[] cipherText = FromHexString(cipherHex);

            using (Aes aes = Aes.Create())
            {
                byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(keyStr));
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs)) return sr.ReadToEnd();
                    }
                }
            }
        }

        private string ToHexString(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        private byte[] FromHexString(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public class Response
        {
            public bool success { get; set; }
            public string message { get; set; }
            public string sessionid { get; set; }
            public string value { get; set; } 
            public string enc { get; set; }
            public string data { get; set; }
            public UserInfo info { get; set; }
        }

        public class UserInfo
        {
            public string username { get; set; }
            public string hwid { get; set; }
            public List<Subscription> subscriptions { get; set; }
        }

        public class Subscription
        {
            public string subscription { get; set; }
            public string expiry { get; set; }
            public int timeleft { get; set; }
        }
    }
}

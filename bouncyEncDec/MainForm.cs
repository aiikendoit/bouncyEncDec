using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using BCChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using System.Linq;


namespace bouncyEncDec
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();

            // Ensure ComboBox has a default selection
            if (cmbAlgorithm != null && cmbAlgorithm.Items.Count > 0)
            {
                cmbAlgorithm.SelectedIndex = 0;
            }
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            cmbAlgorithm.Items.Clear();

            cmbAlgorithm.Items.Insert(0, "Auto (from file)");             //auto detect algorithm
            cmbAlgorithm.Items.Add("AES-256-CBC");
            cmbAlgorithm.Items.Add("AES-256-GCM");
            cmbAlgorithm.Items.Add("AES-128-GCM");
            cmbAlgorithm.Items.Add("ChaCha20-Poly1305");



            // Optional: set a default selection
            cmbAlgorithm.SelectedIndex = 0;

     

        }

        private void btnBrowse_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = "Select file to encrypt/decrypt";
                openFileDialog.Filter = "All Files (*.*)|*.*";

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    txtFilePath.Text = openFileDialog.FileName;
                }
            }
        }

        private void chkShowPassword_CheckedChanged(object sender, EventArgs e)
        {
            txtPassword.UseSystemPasswordChar = !chkShowPassword.Checked;
        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            if (ValidateInputs())
            {
                PerformOperation(true);
            }
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            if (ValidateInputs())
            {
                PerformOperation(false);
            }
        }

        private bool ValidateInputs()
        {
            if (string.IsNullOrEmpty(txtFilePath.Text) || !File.Exists(txtFilePath.Text))
            {
                MessageBox.Show("Please select a valid file.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            if (string.IsNullOrEmpty(txtPassword.Text))
            {
                MessageBox.Show("Please enter a password.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            if (txtPassword.Text.Length < 8)
            {
                MessageBox.Show("Password must be at least 8 characters long.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            if (cmbAlgorithm.SelectedItem == null)
            {
                MessageBox.Show("Please select an encryption algorithm.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }


        private async void PerformOperation(bool encrypt)
        {
            bool hadMismatch = false;
            string mismatchMessage = "";
            string outputFile = "";

            try
            {
                string inputFile = txtFilePath.Text;
                string password = txtPassword.Text;
                string algorithm = cmbAlgorithm.SelectedItem?.ToString() ?? "AES-256-CBC";

                if (string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(algorithm))
                {
                    MessageBox.Show("Invalid input parameters.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (encrypt && algorithm == "Auto (from file)")
                {
                    MessageBox.Show("Please select a specific algorithm for encryption.", "Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                outputFile = encrypt ? inputFile + ".encrypted" : inputFile.Replace(".encrypted", "");

                SetUIState(false);
                progressBar.Visible = true;
                progressBar.Style = ProgressBarStyle.Marquee;
                lblStatus.Text = encrypt ? "Encrypting file..." : "Decrypting file...";

                await System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        if (encrypt)
                            EncryptFile(inputFile, outputFile, password, algorithm);
                        else
                            DecryptFile(inputFile, outputFile, password, algorithm);
                    }
                    catch (InvalidOperationException ex)
                    {
                        hadMismatch = true;
                        mismatchMessage = ex.Message;
                    }
                });

                progressBar.Visible = false;

                if (hadMismatch)
                {
                    lblStatus.ForeColor = Color.Red; // Set text color to red
                    lblStatus.Text = $"Error: {mismatchMessage}";
                    // No popup dialog here — just set status
                    return;
                }

                // ✅ Only reached if no mismatch
                lblStatus.Text = $"Operation completed successfully!\nOutput file: {outputFile}";

                DialogResult result = MessageBox.Show(
                    $"Operation completed successfully!\n\nOutput file: {outputFile}\n\nWould you like to open the output folder?",
                    "Success", MessageBoxButtons.YesNo, MessageBoxIcon.Information);

                if (result == DialogResult.Yes)
                {
                    System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{outputFile}\"");
                    lblStatus.ForeColor = Color.Black;
                    lblStatus.Text = $"Operation completed successfully!\nOutput file: {outputFile}";

                }
            }
            catch (Exception ex)
            {
                progressBar.Visible = false;
                lblStatus.ForeColor = Color.Red;
                lblStatus.Text = $"Error: {ex.Message}";
            }
            finally
            {
                SetUIState(true);
                

            }
        }




        private void SetUIState(bool enabled)
        {
            if (btnBrowse != null) btnBrowse.Enabled = enabled;
            if (btnEncrypt != null) btnEncrypt.Enabled = enabled;
            if (btnDecrypt != null) btnDecrypt.Enabled = enabled;
            if (txtPassword != null) txtPassword.Enabled = enabled;
            if (cmbAlgorithm != null) cmbAlgorithm.Enabled = enabled;
        }

        private void EncryptFile(string inputFile, string outputFile, string password, string algorithm)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFile);
            byte[] salt = GenerateRandomBytes(32);
            byte[] iv = GenerateRandomBytes(GetIVSize(algorithm));

            byte[] key = DeriveKey(password, salt, 32);
            byte[] encryptedData = EncryptData(fileBytes, key, iv, algorithm);

            using (FileStream fs = new FileStream(outputFile, FileMode.Create))
            using (BinaryWriter writer = new BinaryWriter(fs))
            {
                // Write metadata
                writer.Write(Encoding.UTF8.GetBytes("ENC"));  // Magic header
                writer.Write((byte)1);  // Version
                writer.Write(Encoding.UTF8.GetBytes(algorithm));
                writer.Write((byte)0);  // Null terminator for algorithm
                writer.Write(salt.Length);
                writer.Write(salt);
                writer.Write(iv.Length);
                writer.Write(iv);
                writer.Write(encryptedData.Length);
                writer.Write(encryptedData);
            }
        }

        private void DecryptFile(string inputFile, string outputFile, string password, string algorithm)
        {
            using (FileStream fs = new FileStream(inputFile, FileMode.Open))
            using (BinaryReader reader = new BinaryReader(fs))
            {
                // Read and validate header
                byte[] header = reader.ReadBytes(3);
                if (Encoding.UTF8.GetString(header) != "ENC")
                    throw new InvalidOperationException("Invalid encrypted file format");

                byte version = reader.ReadByte();
                if (version != 1)
                    throw new InvalidOperationException("Unsupported file version");

                // Read algorithm
                StringBuilder algBuilder = new StringBuilder();
                byte b;
                while ((b = reader.ReadByte()) != 0)
                {
                    algBuilder.Append((char)b);
                }
                string fileAlgorithm = algBuilder.ToString();

                // Read salt
                int saltLength = reader.ReadInt32();
                byte[] salt = reader.ReadBytes(saltLength);

                // Read IV
                int ivLength = reader.ReadInt32();
                byte[] iv = reader.ReadBytes(ivLength);

                // Read encrypted data
                int dataLength = reader.ReadInt32();
                byte[] encryptedData = reader.ReadBytes(dataLength);

                // Derive key and decrypt
                // If user selected Auto, skip mismatch check and use the file's algorithm
                if (algorithm == "Auto (from file)")
                {
                    algorithm = fileAlgorithm;
                }
                else if (!string.Equals(algorithm, fileAlgorithm, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"Algorithm mismatch. File was encrypted with '{fileAlgorithm}', " +
                        $"but you selected '{algorithm}'. Please choose '{fileAlgorithm}'.");
                }


                // Derive key and decrypt using the (now verified) selected algorithm
                byte[] key = DeriveKey(password, salt, 32);
                byte[] decryptedData = DecryptData(encryptedData, key, iv, algorithm);

                File.WriteAllBytes(outputFile, decryptedData);

            }
        }

        private byte[] EncryptData(byte[] data, byte[] key, byte[] iv, string algorithm)
        {
            switch (algorithm)
            {
                case "AES-256-CBC":
                    return EncryptAesCbc(data, key, iv);
                case "AES-256-GCM":
                    return EncryptAesGcm(data, key, iv);
                case "AES-128-GCM":
                    return EncryptAesGcm(data, key.Take(16).ToArray(), iv); // 128-bit key
                case "ChaCha20-Poly1305":
                    return EncryptChaCha20Poly1305(data, key, iv);
                default:
                    throw new NotSupportedException($"Algorithm {algorithm} is not supported");
            }
        }

        private byte[] DecryptData(byte[] encryptedData, byte[] key, byte[] iv, string algorithm)
        {
            switch (algorithm)
            {
                case "AES-256-CBC":
                    return DecryptAesCbc(encryptedData, key, iv);
                case "AES-256-GCM":
                    return DecryptAesGcm(encryptedData, key, iv);
                case "AES-128-GCM":
                    return DecryptAesGcm(encryptedData, key.Take(16).ToArray(), iv);
                case "ChaCha20-Poly1305":
                    return DecryptChaCha20Poly1305(encryptedData, key, iv);
                default:
                    throw new NotSupportedException($"Algorithm {algorithm} is not supported");
            }
        }

        private byte[] EncryptAesCbc(byte[] data, byte[] key, byte[] iv)
        {
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] output = new byte[cipher.GetOutputSize(data.Length)];
            int len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            cipher.DoFinal(output, len);

            return output;
        }

        private byte[] DecryptAesCbc(byte[] encryptedData, byte[] key, byte[] iv)
        {
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] output = new byte[cipher.GetOutputSize(encryptedData.Length)];
            int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
            len += cipher.DoFinal(output, len);

            byte[] result = new byte[len];
            Array.Copy(output, result, len);
            return result;
        }

        private byte[] EncryptAesGcm(byte[] data, byte[] key, byte[] iv)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, iv));

            byte[] output = new byte[cipher.GetOutputSize(data.Length)];
            int len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            cipher.DoFinal(output, len);

            return output;
        }

        private byte[] DecryptAesGcm(byte[] encryptedData, byte[] key, byte[] iv)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, iv));

            byte[] output = new byte[cipher.GetOutputSize(encryptedData.Length)];
            int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
            len += cipher.DoFinal(output, len);

            byte[] result = new byte[len];
            Array.Copy(output, result, len);
            return result;
        }

        private byte[] EncryptChaCha20Poly1305(byte[] data, byte[] key, byte[] iv)
        {
            var cipher = new BCChaCha20Poly1305();
            cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, iv));

            byte[] output = new byte[cipher.GetOutputSize(data.Length)];
            int len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            cipher.DoFinal(output, len);

            return output;
        }

        private byte[] DecryptChaCha20Poly1305(byte[] encryptedData, byte[] key, byte[] iv)
        {
            var cipher = new BCChaCha20Poly1305();
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, iv));

            byte[] output = new byte[cipher.GetOutputSize(encryptedData.Length)];
            int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
            len += cipher.DoFinal(output, len);

            byte[] result = new byte[len];
            Array.Copy(output, result, len);
            return result;
        }

        private byte[] DeriveKey(string password, byte[] salt, int keyLength)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                return rfc2898.GetBytes(keyLength);
            }
        }

        private byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        private int GetIVSize(string algorithm)
        {
            switch (algorithm)
            {
                case "AES-256-CBC":
                case "AES-256-GCM":
                    return 16;
                case "ChaCha20-Poly1305":
                    return 12;
                default:
                    return 16;
            }
        }


    }



}

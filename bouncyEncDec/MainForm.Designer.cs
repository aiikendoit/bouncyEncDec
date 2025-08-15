namespace bouncyEncDec
{
    partial class MainForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            txtFilePath = new TextBox();
            txtPassword = new TextBox();
            btnBrowse = new Button();
            btnEncrypt = new Button();
            btnDecrypt = new Button();
            progressBar = new ProgressBar();
            lblStatus = new Label();
            cmbAlgorithm = new ComboBox();
            chkShowPassword = new CheckBox();
            SuspendLayout();
            // 
            // txtFilePath
            // 
            txtFilePath.Font = new Font("Segoe UI", 7.8F, FontStyle.Regular, GraphicsUnit.Point, 0);
            txtFilePath.Location = new Point(122, 56);
            txtFilePath.Name = "txtFilePath";
            txtFilePath.Size = new Size(340, 25);
            txtFilePath.TabIndex = 0;
            // 
            // txtPassword
            // 
            txtPassword.Location = new Point(122, 146);
            txtPassword.Name = "txtPassword";
            txtPassword.Size = new Size(340, 34);
            txtPassword.TabIndex = 1;
            txtPassword.UseSystemPasswordChar = true;
            // 
            // btnBrowse
            // 
            btnBrowse.Location = new Point(12, 53);
            btnBrowse.Name = "btnBrowse";
            btnBrowse.Size = new Size(94, 41);
            btnBrowse.TabIndex = 2;
            btnBrowse.Text = "Browse";
            btnBrowse.UseVisualStyleBackColor = true;
            btnBrowse.Click += btnBrowse_Click;
            // 
            // btnEncrypt
            // 
            btnEncrypt.Location = new Point(122, 232);
            btnEncrypt.Name = "btnEncrypt";
            btnEncrypt.Size = new Size(94, 41);
            btnEncrypt.TabIndex = 3;
            btnEncrypt.Text = "Encrypt";
            btnEncrypt.UseVisualStyleBackColor = true;
            btnEncrypt.Click += btnEncrypt_Click;
            // 
            // btnDecrypt
            // 
            btnDecrypt.Location = new Point(240, 234);
            btnDecrypt.Name = "btnDecrypt";
            btnDecrypt.Size = new Size(94, 39);
            btnDecrypt.TabIndex = 4;
            btnDecrypt.Text = "Decrypt";
            btnDecrypt.UseVisualStyleBackColor = true;
            btnDecrypt.Click += btnDecrypt_Click;
            // 
            // progressBar
            // 
            progressBar.Location = new Point(12, 347);
            progressBar.Name = "progressBar";
            progressBar.Size = new Size(450, 29);
            progressBar.TabIndex = 5;
            // 
            // lblStatus
            // 
            lblStatus.Font = new Font("Segoe UI", 7.8F, FontStyle.Regular, GraphicsUnit.Point, 0);
            lblStatus.Location = new Point(12, 308);
            lblStatus.MaximumSize = new Size(498, 60);
            lblStatus.Name = "lblStatus";
            lblStatus.Size = new Size(450, 36);
            lblStatus.TabIndex = 6;
            lblStatus.Text = "Status";
            // 
            // cmbAlgorithm
            // 
            cmbAlgorithm.FormattingEnabled = true;
            cmbAlgorithm.Location = new Point(122, 100);
            cmbAlgorithm.Name = "cmbAlgorithm";
            cmbAlgorithm.Size = new Size(340, 36);
            cmbAlgorithm.TabIndex = 7;
            // 
            // chkShowPassword
            // 
            chkShowPassword.AutoSize = true;
            chkShowPassword.Location = new Point(122, 190);
            chkShowPassword.Name = "chkShowPassword";
            chkShowPassword.Size = new Size(167, 32);
            chkShowPassword.TabIndex = 8;
            chkShowPassword.Text = "show password";
            chkShowPassword.UseVisualStyleBackColor = true;
            chkShowPassword.CheckedChanged += chkShowPassword_CheckedChanged;
            // 
            // MainForm
            // 
            AutoScaleDimensions = new SizeF(11F, 28F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(480, 388);
            Controls.Add(chkShowPassword);
            Controls.Add(cmbAlgorithm);
            Controls.Add(lblStatus);
            Controls.Add(progressBar);
            Controls.Add(btnDecrypt);
            Controls.Add(btnEncrypt);
            Controls.Add(btnBrowse);
            Controls.Add(txtPassword);
            Controls.Add(txtFilePath);
            Font = new Font("Segoe UI", 12F, FontStyle.Regular, GraphicsUnit.Point, 0);
            Margin = new Padding(4);
            MaximizeBox = false;
            MaximumSize = new Size(498, 435);
            MinimizeBox = false;
            MinimumSize = new Size(498, 435);
            Name = "MainForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "File Encyption Decryption App";
            Load += MainForm_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private TextBox txtFilePath;
        private TextBox txtPassword;
        private Button btnBrowse;
        private Button btnEncrypt;
        private Button btnDecrypt;
        private ProgressBar progressBar;
        private Label lblStatus;
        private ComboBox cmbAlgorithm;
        private CheckBox chkShowPassword;
    }
}

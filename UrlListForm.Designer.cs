using System.Windows.Forms;

namespace SecurityHeaderScannerGUI
{
    partial class UrlListForm
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.TextBox txtUrls;
        private System.Windows.Forms.Button btnOk;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null)) components.Dispose();
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.txtUrls = new System.Windows.Forms.TextBox();
            this.btnOk = new System.Windows.Forms.Button();
            this.SuspendLayout();

            // txtUrls
            this.txtUrls.Multiline = true;
            this.txtUrls.ScrollBars = ScrollBars.Vertical;
            this.txtUrls.Location = new System.Drawing.Point(12, 12);
            this.txtUrls.Size = new System.Drawing.Size(460, 220);
            this.txtUrls.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;

            // btnOk
            this.btnOk.Text = "Adicionar";
            this.btnOk.Location = new System.Drawing.Point(372, 240);
            this.btnOk.Size = new System.Drawing.Size(100, 35);
            this.btnOk.Click += new System.EventHandler(this.btnOk_Click);

            // UrlListForm
            this.ClientSize = new System.Drawing.Size(484, 281);
            this.Controls.Add(this.txtUrls);
            this.Controls.Add(this.btnOk);
            this.Text = "Adicionar URLs em lote";

            this.ResumeLayout(false);
            this.PerformLayout();
        }
    }
}
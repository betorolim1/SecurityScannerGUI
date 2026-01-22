namespace SecurityHeaderScannerGUI
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.FlowLayoutPanel flowUrls;
        private System.Windows.Forms.Button btnAdd;
        private System.Windows.Forms.Button btnScan;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null)) components.Dispose();
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.flowUrls = new System.Windows.Forms.FlowLayoutPanel();
            this.btnAdd = new System.Windows.Forms.Button();
            this.btnScan = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // flowUrls
            // 
            this.flowUrls.AutoScroll = true;
            this.flowUrls.FlowDirection = System.Windows.Forms.FlowDirection.TopDown;
            this.flowUrls.WrapContents = false;
            this.flowUrls.Location = new System.Drawing.Point(12, 12);
            this.flowUrls.Name = "flowUrls";
            this.flowUrls.Size = new System.Drawing.Size(560, 300);
            this.flowUrls.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            // 
            // btnAdd
            // 
            this.btnAdd.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.btnAdd.Location = new System.Drawing.Point(12, 320);
            this.btnAdd.Name = "btnAdd";
            this.btnAdd.Size = new System.Drawing.Size(140, 40);
            this.btnAdd.TabIndex = 1;
            this.btnAdd.Text = "+ Adicionar URL";
            this.btnAdd.UseVisualStyleBackColor = true;
            this.btnAdd.Click += new System.EventHandler(this.btnAdd_Click);
            // 
            // btnScan
            // 
            this.btnScan.Font = new System.Drawing.Font("Segoe UI", 10F, System.Drawing.FontStyle.Bold);
            this.btnScan.Location = new System.Drawing.Point(452, 320);
            this.btnScan.Name = "btnScan";
            this.btnScan.Size = new System.Drawing.Size(120, 40);
            this.btnScan.TabIndex = 2;
            this.btnScan.Text = "Iniciar Scan";
            this.btnScan.UseVisualStyleBackColor = true;
            this.btnScan.Click += new System.EventHandler(this.btnScan_Click);
            // 
            // MainForm
            // 
            this.ClientSize = new System.Drawing.Size(584, 381);
            this.Controls.Add(this.flowUrls);
            this.Controls.Add(this.btnAdd);
            this.Controls.Add(this.btnScan);
            this.Name = "MainForm";
            this.Text = "Security Header Scanner GUI";
            this.ResumeLayout(false);
        }
    }
}

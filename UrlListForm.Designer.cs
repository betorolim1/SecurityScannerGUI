namespace SecurityHeaderScannerGUI
{
    partial class UrlListForm
    {
        private System.ComponentModel.IContainer components = null;

        // Header
        private System.Windows.Forms.Panel panelHeader;
        private System.Windows.Forms.Label lblTitle;
        private System.Windows.Forms.Label lblSubtitle;

        // Área de texto
        private System.Windows.Forms.TextBox txtUrls;

        // Rodapé
        private System.Windows.Forms.Panel panelFooter;
        private System.Windows.Forms.Label lblCount;
        private System.Windows.Forms.Button btnCancel;
        private System.Windows.Forms.Button btnOk;

        // Tooltip
        private System.Windows.Forms.ToolTip toolTip;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null)) components.Dispose();
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();

            this.panelHeader = new System.Windows.Forms.Panel();
            this.lblTitle = new System.Windows.Forms.Label();
            this.lblSubtitle = new System.Windows.Forms.Label();

            this.txtUrls = new System.Windows.Forms.TextBox();

            this.panelFooter = new System.Windows.Forms.Panel();
            this.lblCount = new System.Windows.Forms.Label();
            this.btnCancel = new System.Windows.Forms.Button();
            this.btnOk = new System.Windows.Forms.Button();

            this.toolTip = new System.Windows.Forms.ToolTip(this.components);

            this.SuspendLayout();
            this.panelHeader.SuspendLayout();
            this.panelFooter.SuspendLayout();

            // ═══════════════════════════════════════════
            // Cores do tema dark
            // ═══════════════════════════════════════════
            var bgDark = System.Drawing.Color.FromArgb(24, 24, 32);
            var bgHeader = System.Drawing.Color.FromArgb(18, 18, 26);
            var bgInput = System.Drawing.Color.FromArgb(55, 58, 75);
            var textPrimary = System.Drawing.Color.FromArgb(230, 232, 240);
            var textSecondary = System.Drawing.Color.FromArgb(140, 145, 165);
            var accentGreen = System.Drawing.Color.FromArgb(46, 204, 113);
            var borderColor = System.Drawing.Color.FromArgb(50, 54, 68);
            var btnSecondaryBg = System.Drawing.Color.FromArgb(44, 47, 60);
            var btnSecondaryHover = System.Drawing.Color.FromArgb(55, 58, 72);

            // ═══════════════════════════════════════════
            // panelHeader
            // ═══════════════════════════════════════════
            this.panelHeader.BackColor = bgHeader;
            this.panelHeader.Dock = System.Windows.Forms.DockStyle.Top;
            this.panelHeader.Height = 60;

            this.lblTitle.AutoSize = true;
            this.lblTitle.Text = "Adicionar URLs em lote";
            this.lblTitle.Font = new System.Drawing.Font("Segoe UI", 13F, System.Drawing.FontStyle.Bold);
            this.lblTitle.ForeColor = textPrimary;
            this.lblTitle.Location = new System.Drawing.Point(20, 10);
            this.lblTitle.BackColor = bgHeader;

            this.lblSubtitle.AutoSize = true;
            this.lblSubtitle.Text = "Cole uma URL por linha";
            this.lblSubtitle.Font = new System.Drawing.Font("Segoe UI", 9F);
            this.lblSubtitle.ForeColor = textSecondary;
            this.lblSubtitle.Location = new System.Drawing.Point(22, 36);
            this.lblSubtitle.BackColor = bgHeader;

            this.panelHeader.Controls.Add(this.lblTitle);
            this.panelHeader.Controls.Add(this.lblSubtitle);

            // ═══════════════════════════════════════════
            // txtUrls — área de texto principal
            // ═══════════════════════════════════════════
            this.txtUrls.Multiline = true;
            this.txtUrls.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtUrls.WordWrap = false;
            this.txtUrls.BackColor = bgInput;
            this.txtUrls.ForeColor = textPrimary;
            this.txtUrls.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.txtUrls.Font = new System.Drawing.Font("Consolas", 10F);
            this.txtUrls.Location = new System.Drawing.Point(20, 72);
            this.txtUrls.Size = new System.Drawing.Size(480, 240);
            this.txtUrls.Anchor = System.Windows.Forms.AnchorStyles.Top
                                | System.Windows.Forms.AnchorStyles.Bottom
                                | System.Windows.Forms.AnchorStyles.Left
                                | System.Windows.Forms.AnchorStyles.Right;

            // ═══════════════════════════════════════════
            // panelFooter — botões e contagem
            // ═══════════════════════════════════════════
            this.panelFooter.BackColor = bgDark;
            this.panelFooter.Location = new System.Drawing.Point(20, 320);
            this.panelFooter.Size = new System.Drawing.Size(480, 48);
            this.panelFooter.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                                    | System.Windows.Forms.AnchorStyles.Left
                                    | System.Windows.Forms.AnchorStyles.Right;

            // lblCount — contagem de URLs digitadas
            this.lblCount.AutoSize = false;
            this.lblCount.Text = "0 URLs detectadas";
            this.lblCount.Font = new System.Drawing.Font("Segoe UI", 9F);
            this.lblCount.ForeColor = textSecondary;
            this.lblCount.BackColor = bgDark;
            this.lblCount.Location = new System.Drawing.Point(0, 14);
            this.lblCount.Size = new System.Drawing.Size(200, 20);
            this.lblCount.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.lblCount.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                                 | System.Windows.Forms.AnchorStyles.Left;

            // btnCancel
            this.btnCancel.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnCancel.FlatAppearance.BorderColor = borderColor;
            this.btnCancel.FlatAppearance.BorderSize = 1;
            this.btnCancel.FlatAppearance.MouseOverBackColor = btnSecondaryHover;
            this.btnCancel.BackColor = btnSecondaryBg;
            this.btnCancel.ForeColor = textPrimary;
            this.btnCancel.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.btnCancel.Size = new System.Drawing.Size(100, 36);
            this.btnCancel.Location = new System.Drawing.Point(248, 6);
            this.btnCancel.Text = "Cancelar";
            this.btnCancel.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnCancel.TabIndex = 2;
            this.btnCancel.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                                  | System.Windows.Forms.AnchorStyles.Right;
            this.btnCancel.Click += new System.EventHandler(this.btnCancel_Click);

            // btnOk — destaque verde
            this.btnOk.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnOk.FlatAppearance.BorderSize = 0;
            this.btnOk.FlatAppearance.MouseOverBackColor = System.Drawing.Color.FromArgb(36, 180, 96);
            this.btnOk.BackColor = accentGreen;
            this.btnOk.ForeColor = System.Drawing.Color.FromArgb(10, 10, 10);
            this.btnOk.Font = new System.Drawing.Font("Segoe UI", 10F, System.Drawing.FontStyle.Bold);
            this.btnOk.Size = new System.Drawing.Size(120, 36);
            this.btnOk.Location = new System.Drawing.Point(356, 6);
            this.btnOk.Text = "Adicionar";
            this.btnOk.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnOk.TabIndex = 1;
            this.btnOk.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                              | System.Windows.Forms.AnchorStyles.Right;
            this.btnOk.Click += new System.EventHandler(this.btnOk_Click);

            this.panelFooter.Controls.Add(this.lblCount);
            this.panelFooter.Controls.Add(this.btnCancel);
            this.panelFooter.Controls.Add(this.btnOk);

            // ═══════════════════════════════════════════
            // Tooltips
            // ═══════════════════════════════════════════
            this.toolTip.SetToolTip(this.btnOk, "Adicionar todas as URLs à lista principal");
            this.toolTip.SetToolTip(this.btnCancel, "Fechar sem adicionar");
            this.toolTip.SetToolTip(this.txtUrls, "Cole ou digite uma URL por linha");

            // ═══════════════════════════════════════════
            // UrlListForm
            // ═══════════════════════════════════════════
            this.BackColor = bgDark;
            this.ForeColor = textPrimary;
            this.ClientSize = new System.Drawing.Size(520, 380);
            this.MinimumSize = new System.Drawing.Size(420, 300);
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.AcceptButton = this.btnOk;
            this.CancelButton = this.btnCancel;

            this.Controls.Add(this.txtUrls);
            this.Controls.Add(this.panelFooter);
            this.Controls.Add(this.panelHeader);

            this.Name = "UrlListForm";
            this.Text = "Adicionar URLs em lote";

            this.panelHeader.ResumeLayout(false);
            this.panelHeader.PerformLayout();
            this.panelFooter.ResumeLayout(false);
            this.ResumeLayout(false);
        }
    }
}

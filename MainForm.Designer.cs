namespace SecurityHeaderScannerGUI
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;

        // Header
        private System.Windows.Forms.Panel panelHeader;
        private System.Windows.Forms.Label lblIcon;
        private System.Windows.Forms.Label lblTitle;
        private System.Windows.Forms.Label lblSubtitle;

        // Área de URLs
        private System.Windows.Forms.Panel panelUrlContainer;
        private System.Windows.Forms.Label lblUrlsHeader;
        private System.Windows.Forms.FlowLayoutPanel flowUrls;

        // Botões
        private System.Windows.Forms.Panel panelActions;
        private System.Windows.Forms.Button btnAdd;
        private System.Windows.Forms.Button btnAddList;
        private System.Windows.Forms.Button btnScan;

        // Progress
        private System.Windows.Forms.ProgressBar progressBar;

        // Status bar
        private System.Windows.Forms.Panel panelStatus;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.Label lblUrlCount;

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
            this.lblIcon = new System.Windows.Forms.Label();
            this.lblTitle = new System.Windows.Forms.Label();
            this.lblSubtitle = new System.Windows.Forms.Label();

            this.panelUrlContainer = new System.Windows.Forms.Panel();
            this.lblUrlsHeader = new System.Windows.Forms.Label();
            this.flowUrls = new System.Windows.Forms.FlowLayoutPanel();

            this.panelActions = new System.Windows.Forms.Panel();
            this.btnAdd = new System.Windows.Forms.Button();
            this.btnAddList = new System.Windows.Forms.Button();
            this.btnScan = new System.Windows.Forms.Button();

            this.progressBar = new System.Windows.Forms.ProgressBar();

            this.panelStatus = new System.Windows.Forms.Panel();
            this.lblStatus = new System.Windows.Forms.Label();
            this.lblUrlCount = new System.Windows.Forms.Label();

            this.toolTip = new System.Windows.Forms.ToolTip(this.components);

            this.SuspendLayout();
            this.panelHeader.SuspendLayout();
            this.panelUrlContainer.SuspendLayout();
            this.panelActions.SuspendLayout();
            this.panelStatus.SuspendLayout();

            // ═══════════════════════════════════════════
            // Cores do tema dark
            // ═══════════════════════════════════════════
            var bgDark = System.Drawing.Color.FromArgb(24, 24, 32);
            var bgCard = System.Drawing.Color.FromArgb(32, 34, 44);
            var bgHeader = System.Drawing.Color.FromArgb(18, 18, 26);
            var bgStatus = System.Drawing.Color.FromArgb(18, 18, 26);
            var textPrimary = System.Drawing.Color.FromArgb(230, 232, 240);
            var textSecondary = System.Drawing.Color.FromArgb(140, 145, 165);
            var accentGreen = System.Drawing.Color.FromArgb(46, 204, 113);
            var borderColor = System.Drawing.Color.FromArgb(50, 54, 68);
            var btnSecondaryBg = System.Drawing.Color.FromArgb(44, 47, 60);
            var btnSecondaryHover = System.Drawing.Color.FromArgb(55, 58, 72);

            // ═══════════════════════════════════════════
            // panelHeader — barra superior com ícone
            // ═══════════════════════════════════════════
            this.panelHeader.BackColor = bgHeader;
            this.panelHeader.Dock = System.Windows.Forms.DockStyle.Top;
            this.panelHeader.Height = 82;

            this.lblIcon.AutoSize = true;
            this.lblIcon.Text = "\U0001F6E1";
            this.lblIcon.Font = new System.Drawing.Font("Segoe UI Emoji", 22F);
            this.lblIcon.ForeColor = accentGreen;
            this.lblIcon.Location = new System.Drawing.Point(16, 12);
            this.lblIcon.BackColor = bgHeader;

            this.lblTitle.AutoSize = true;
            this.lblTitle.Text = "Security Header Scanner";
            this.lblTitle.Font = new System.Drawing.Font("Segoe UI", 15F, System.Drawing.FontStyle.Bold);
            this.lblTitle.ForeColor = textPrimary;
            this.lblTitle.Location = new System.Drawing.Point(72, 14);
            this.lblTitle.BackColor = bgHeader;

            this.lblSubtitle.AutoSize = true;
            this.lblSubtitle.Text = "Análise de cabeçalhos de segurança HTTP";
            this.lblSubtitle.Font = new System.Drawing.Font("Segoe UI", 9F);
            this.lblSubtitle.ForeColor = textSecondary;
            this.lblSubtitle.Location = new System.Drawing.Point(74, 54);
            this.lblSubtitle.BackColor = bgHeader;

            this.panelHeader.Controls.Add(this.lblTitle);
            this.panelHeader.Controls.Add(this.lblSubtitle);
            this.panelHeader.Controls.Add(this.lblIcon);

            // ═══════════════════════════════════════════
            // panelUrlContainer — card com a lista de URLs
            // ═══════════════════════════════════════════
            this.panelUrlContainer.BackColor = bgCard;
            this.panelUrlContainer.Location = new System.Drawing.Point(20, 84);
            this.panelUrlContainer.Size = new System.Drawing.Size(710, 380);
            this.panelUrlContainer.Anchor = System.Windows.Forms.AnchorStyles.Top
                                          | System.Windows.Forms.AnchorStyles.Bottom
                                          | System.Windows.Forms.AnchorStyles.Left
                                          | System.Windows.Forms.AnchorStyles.Right;

            // lblUrlsHeader — posição fixa no topo do card
            this.lblUrlsHeader.Text = "  URLs para análise";
            this.lblUrlsHeader.Font = new System.Drawing.Font("Segoe UI Semibold", 10F);
            this.lblUrlsHeader.ForeColor = textSecondary;
            this.lblUrlsHeader.BackColor = System.Drawing.Color.FromArgb(28, 30, 40);
            this.lblUrlsHeader.Location = new System.Drawing.Point(0, 0);
            this.lblUrlsHeader.Size = new System.Drawing.Size(710, 34);
            this.lblUrlsHeader.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.lblUrlsHeader.Padding = new System.Windows.Forms.Padding(8, 0, 0, 0);
            this.lblUrlsHeader.Anchor = System.Windows.Forms.AnchorStyles.Top
                                       | System.Windows.Forms.AnchorStyles.Left
                                       | System.Windows.Forms.AnchorStyles.Right;

            // flowUrls — posição fixa abaixo do header, preenche o resto
            this.flowUrls.AutoScroll = true;
            this.flowUrls.FlowDirection = System.Windows.Forms.FlowDirection.TopDown;
            this.flowUrls.WrapContents = false;
            this.flowUrls.BackColor = bgCard;
            this.flowUrls.Location = new System.Drawing.Point(0, 34);
            this.flowUrls.Size = new System.Drawing.Size(710, 346);
            this.flowUrls.Padding = new System.Windows.Forms.Padding(8, 6, 8, 6);
            this.flowUrls.Anchor = System.Windows.Forms.AnchorStyles.Top
                                  | System.Windows.Forms.AnchorStyles.Bottom
                                  | System.Windows.Forms.AnchorStyles.Left
                                  | System.Windows.Forms.AnchorStyles.Right;

            this.panelUrlContainer.Controls.Add(this.lblUrlsHeader);
            this.panelUrlContainer.Controls.Add(this.flowUrls);

            // ═══════════════════════════════════════════
            // progressBar — linha fina entre card e botões
            // ═══════════════════════════════════════════
            this.progressBar.Style = System.Windows.Forms.ProgressBarStyle.Continuous;
            this.progressBar.Location = new System.Drawing.Point(20, 468);
            this.progressBar.Size = new System.Drawing.Size(710, 4);
            this.progressBar.Minimum = 0;
            this.progressBar.Maximum = 100;
            this.progressBar.Value = 0;
            this.progressBar.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                                    | System.Windows.Forms.AnchorStyles.Left
                                    | System.Windows.Forms.AnchorStyles.Right;

            // ═══════════════════════════════════════════
            // panelActions — barra de botões
            // ═══════════════════════════════════════════
            this.panelActions.BackColor = bgDark;
            this.panelActions.Location = new System.Drawing.Point(20, 476);
            this.panelActions.Size = new System.Drawing.Size(710, 52);
            this.panelActions.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                                     | System.Windows.Forms.AnchorStyles.Left
                                     | System.Windows.Forms.AnchorStyles.Right;

            this.btnAdd.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnAdd.FlatAppearance.BorderColor = borderColor;
            this.btnAdd.FlatAppearance.BorderSize = 1;
            this.btnAdd.FlatAppearance.MouseOverBackColor = btnSecondaryHover;
            this.btnAdd.BackColor = btnSecondaryBg;
            this.btnAdd.ForeColor = textPrimary;
            this.btnAdd.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.btnAdd.Size = new System.Drawing.Size(145, 38);
            this.btnAdd.Location = new System.Drawing.Point(0, 7);
            this.btnAdd.Text = "+  Adicionar URL";
            this.btnAdd.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnAdd.TabIndex = 1;
            this.btnAdd.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                               | System.Windows.Forms.AnchorStyles.Left;
            this.btnAdd.Click += new System.EventHandler(this.btnAdd_Click);

            this.btnAddList.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnAddList.FlatAppearance.BorderColor = borderColor;
            this.btnAddList.FlatAppearance.BorderSize = 1;
            this.btnAddList.FlatAppearance.MouseOverBackColor = btnSecondaryHover;
            this.btnAddList.BackColor = btnSecondaryBg;
            this.btnAddList.ForeColor = textPrimary;
            this.btnAddList.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.btnAddList.Size = new System.Drawing.Size(165, 38);
            this.btnAddList.Location = new System.Drawing.Point(153, 7);
            this.btnAddList.Text = "\u2630  Adicionar por lista";
            this.btnAddList.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnAddList.TabIndex = 2;
            this.btnAddList.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                                   | System.Windows.Forms.AnchorStyles.Left;
            this.btnAddList.Click += new System.EventHandler(this.btnAddList_Click);

            this.btnScan.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnScan.FlatAppearance.BorderSize = 0;
            this.btnScan.FlatAppearance.MouseOverBackColor = System.Drawing.Color.FromArgb(36, 180, 96);
            this.btnScan.BackColor = accentGreen;
            this.btnScan.ForeColor = System.Drawing.Color.FromArgb(10, 10, 10);
            this.btnScan.Font = new System.Drawing.Font("Segoe UI", 10F, System.Drawing.FontStyle.Bold);
            this.btnScan.Size = new System.Drawing.Size(148, 38);
            this.btnScan.Location = new System.Drawing.Point(562, 7);
            this.btnScan.Text = "\u25B6  Iniciar Scan";
            this.btnScan.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnScan.TabIndex = 3;
            this.btnScan.Anchor = System.Windows.Forms.AnchorStyles.Bottom
                                | System.Windows.Forms.AnchorStyles.Right;
            this.btnScan.Click += new System.EventHandler(this.btnScan_Click);

            this.panelActions.Controls.Add(this.btnAdd);
            this.panelActions.Controls.Add(this.btnAddList);
            this.panelActions.Controls.Add(this.btnScan);

            // ═══════════════════════════════════════════
            // panelStatus — status bar inferior
            // ═══════════════════════════════════════════
            this.panelStatus.BackColor = bgStatus;
            this.panelStatus.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.panelStatus.Height = 28;

            this.lblStatus.AutoSize = false;
            this.lblStatus.Text = "Pronto";
            this.lblStatus.Font = new System.Drawing.Font("Segoe UI", 8.5F);
            this.lblStatus.ForeColor = textSecondary;
            this.lblStatus.BackColor = bgStatus;
            this.lblStatus.Dock = System.Windows.Forms.DockStyle.Left;
            this.lblStatus.Width = 400;
            this.lblStatus.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.lblStatus.Padding = new System.Windows.Forms.Padding(12, 0, 0, 0);

            this.lblUrlCount.AutoSize = false;
            this.lblUrlCount.Text = "URLs: 1";
            this.lblUrlCount.Font = new System.Drawing.Font("Segoe UI", 8.5F);
            this.lblUrlCount.ForeColor = textSecondary;
            this.lblUrlCount.BackColor = bgStatus;
            this.lblUrlCount.Dock = System.Windows.Forms.DockStyle.Right;
            this.lblUrlCount.Width = 120;
            this.lblUrlCount.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lblUrlCount.Padding = new System.Windows.Forms.Padding(0, 0, 12, 0);

            this.panelStatus.Controls.Add(this.lblStatus);
            this.panelStatus.Controls.Add(this.lblUrlCount);

            // ═══════════════════════════════════════════
            // Tooltips
            // ═══════════════════════════════════════════
            this.toolTip.BackColor = System.Drawing.Color.FromArgb(50, 54, 68);
            this.toolTip.ForeColor = textPrimary;
            this.toolTip.SetToolTip(this.btnAdd, "Adicionar um novo campo de URL");
            this.toolTip.SetToolTip(this.btnAddList, "Colar uma lista de URLs de uma só vez");
            this.toolTip.SetToolTip(this.btnScan, "Executar análise de cabeçalhos HTTP em todas as URLs");

            // ═══════════════════════════════════════════
            // MainForm
            // ═══════════════════════════════════════════
            this.BackColor = bgDark;
            this.ForeColor = textPrimary;
            this.ClientSize = new System.Drawing.Size(750, 550);
            this.MinimumSize = new System.Drawing.Size(540, 360);
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Font = new System.Drawing.Font("Segoe UI", 9.5F);

            this.Controls.Add(this.panelUrlContainer);
            this.Controls.Add(this.progressBar);
            this.Controls.Add(this.panelActions);
            this.Controls.Add(this.panelHeader);
            this.Controls.Add(this.panelStatus);

            this.Name = "MainForm";
            this.Text = "Security Header Scanner";

            this.panelHeader.ResumeLayout(false);
            this.panelHeader.PerformLayout();
            this.panelUrlContainer.ResumeLayout(false);
            this.panelActions.ResumeLayout(false);
            this.panelStatus.ResumeLayout(false);
            this.ResumeLayout(false);
        }
    }
}

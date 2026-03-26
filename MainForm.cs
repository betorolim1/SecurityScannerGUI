using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using Button = System.Windows.Forms.Button;
using TextBox = System.Windows.Forms.TextBox;

namespace SecurityHeaderScannerGUI
{
    public partial class MainForm : Form
    {
        // Cores reutilizáveis do tema dark
        private readonly System.Drawing.Color _bgInput = System.Drawing.Color.FromArgb(55, 58, 75);
        private readonly System.Drawing.Color _bgCard = System.Drawing.Color.FromArgb(32, 34, 44);
        private readonly System.Drawing.Color _textPrimary = System.Drawing.Color.FromArgb(230, 232, 240);
        private readonly System.Drawing.Color _textSecondary = System.Drawing.Color.FromArgb(140, 145, 165);
        private readonly System.Drawing.Color _borderColor = System.Drawing.Color.FromArgb(50, 54, 68);
        private readonly System.Drawing.Color _btnDangerBg = System.Drawing.Color.FromArgb(180, 60, 60);
        private readonly System.Drawing.Color _btnDangerHover = System.Drawing.Color.FromArgb(200, 75, 75);

        public MainForm()
        {
            InitializeComponent();

            this.Load += (s, e) => AddUrlField();

            flowUrls.Resize += (s, e) =>
            {
                foreach (Control c in flowUrls.Controls)
                {
                    if (c is Panel p)
                        p.Width = flowUrls.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4;
                }
            };
        }

        private void UpdateUrlCount()
        {
            int count = flowUrls.Controls.OfType<Panel>().Count();
            lblUrlCount.Text = $"URLs: {count}";
        }

        private void AddUrlField(string? initialValue = null)
        {
            var panel = new Panel();
            panel.Width = flowUrls.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4;
            panel.Height = 38;
            panel.Margin = new Padding(3, 3, 3, 3);
            panel.BackColor = _bgCard;

            var txt = new TextBox();
            txt.Width = panel.Width - 48;
            txt.Height = 28;
            txt.Left = 0;
            txt.Top = 5;
            txt.BackColor = _bgInput;
            txt.ForeColor = _textPrimary;
            txt.BorderStyle = BorderStyle.FixedSingle;
            txt.Font = new System.Drawing.Font("Segoe UI", 10F);
            txt.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top;
            if (!string.IsNullOrEmpty(initialValue)) txt.Text = initialValue;

            var btnRemove = new Button();
            btnRemove.Text = "\u2715";
            btnRemove.Width = 36;
            btnRemove.Height = 28;
            btnRemove.Left = txt.Width + 8;
            btnRemove.Top = 5;
            btnRemove.FlatStyle = FlatStyle.Flat;
            btnRemove.FlatAppearance.BorderSize = 0;
            btnRemove.FlatAppearance.MouseOverBackColor = _btnDangerHover;
            btnRemove.BackColor = _btnDangerBg;
            btnRemove.ForeColor = _textPrimary;
            btnRemove.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            btnRemove.Cursor = Cursors.Hand;
            btnRemove.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            toolTip.SetToolTip(btnRemove, "Remover esta URL");

            btnRemove.Click += (s, e) =>
            {
                flowUrls.Controls.Remove(panel);
                panel.Dispose();
                UpdateUrlCount();
            };

            panel.Controls.Add(txt);
            panel.Controls.Add(btnRemove);

            flowUrls.Controls.Add(panel);
            UpdateUrlCount();
        }

        private void btnAdd_Click(object sender, EventArgs e)
        {
            var lastPanel = flowUrls.Controls.OfType<Panel>().LastOrDefault();
            if (lastPanel != null)
            {
                var lastTxt = lastPanel.Controls.OfType<TextBox>().FirstOrDefault();
                if (lastTxt != null && string.IsNullOrWhiteSpace(lastTxt.Text))
                {
                    lastTxt.Focus();
                    return;
                }
            }

            AddUrlField();
        }

        private async void btnScan_Click(object sender, EventArgs e)
        {
            var urls = new List<string>();

            foreach (Control c in flowUrls.Controls)
            {
                if (c is Panel p)
                {
                    var txt = p.Controls.OfType<TextBox>().FirstOrDefault();
                    if (txt != null && !string.IsNullOrWhiteSpace(txt.Text))
                        urls.Add(txt.Text.Trim());
                }
            }

            if (urls.Count == 0)
            {
                MessageBox.Show("Insira pelo menos uma URL.", "Atenção",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            progressBar.Value = 0;
            btnScan.Enabled = false;
            btnAdd.Enabled = false;
            btnAddList.Enabled = false;
            btnScan.Text = "⏳  Analisando...";
            lblStatus.Text = $"Analisando {urls.Count} URL(s)...";

            try
            {
                string report = await Scanner.RunScan(urls, p =>
                {
                    progressBar.Value = p;
                });

                lblStatus.Text = $"Concluído — {urls.Count} URL(s) analisada(s) em {DateTime.Now:HH:mm:ss}";

                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = report,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                lblStatus.Text = $"Erro: {ex.Message}";
                MessageBox.Show(ex.Message, "Erro no scan",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            btnScan.Enabled = true;
            btnAdd.Enabled = true;
            btnAddList.Enabled = true;
            btnScan.Text = "\u25B6  Iniciar Scan";
        }

        private void btnAddList_Click(object sender, EventArgs e)
        {
            var form = new UrlListForm();

            if (form.ShowDialog() == DialogResult.OK)
            {
                var urls = form.UrlsText
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim())
                    .Where(u => !string.IsNullOrWhiteSpace(u));

                if (urls.Any())
                {
                    var lastPanel = flowUrls.Controls.OfType<Panel>().LastOrDefault();
                    if (lastPanel != null)
                    {
                        var lastTxt = lastPanel.Controls.OfType<TextBox>().FirstOrDefault();
                        if (lastTxt != null && string.IsNullOrWhiteSpace(lastTxt.Text))
                        {
                            flowUrls.Controls.Remove(lastPanel);
                            lastPanel.Dispose();
                        }
                    }

                    foreach (var url in urls)
                        AddUrlField(url);
                }
            }
        }
    }
}

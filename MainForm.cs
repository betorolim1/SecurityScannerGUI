using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace SecurityHeaderScannerGUI
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
            AddUrlField(); // cria o primeiro campo automaticamente
        }

        private void AddUrlField(string? initialValue = null)
        {
            var panel = new Panel();
            panel.Width = flowUrls.ClientSize.Width - 5;
            panel.Height = 36;
            panel.Margin = new Padding(3);

            var txt = new TextBox();
            txt.Width = panel.Width - 45;
            txt.Left = 0;
            txt.Top = 5;
            txt.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top;
            if (!string.IsNullOrEmpty(initialValue)) txt.Text = initialValue;

            var btnRemove = new Button();
            btnRemove.Text = "X";
            btnRemove.Width = 36;
            btnRemove.Height = 26;
            btnRemove.Left = txt.Width + 6;
            btnRemove.Top = 4;
            btnRemove.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            btnRemove.Click += (s, e) =>
            {
                flowUrls.Controls.Remove(panel);
                panel.Dispose();
            };

            panel.Controls.Add(txt);
            panel.Controls.Add(btnRemove);

            // Adiciona no FlowLayoutPanel
            flowUrls.Controls.Add(panel);
        }

        private void btnAdd_Click(object sender, EventArgs e)
        {
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
                MessageBox.Show("Insira pelo menos uma URL.");
                return;
            }

            btnScan.Enabled = false;
            btnAdd.Enabled = false;

            try
            {
                string report = await Scanner.RunScan(urls);
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = report,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

            btnScan.Enabled = true;
            btnAdd.Enabled = true;
        }
    }
}

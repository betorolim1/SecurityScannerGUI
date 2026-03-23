using System;
using System.Linq;
using System.Windows.Forms;

namespace SecurityHeaderScannerGUI
{
    public partial class UrlListForm : Form
    {
        public string UrlsText => txtUrls.Text;

        private readonly System.Drawing.Color _placeholderColor = System.Drawing.Color.FromArgb(100, 104, 120);
        private readonly System.Drawing.Color _textColor = System.Drawing.Color.FromArgb(230, 232, 240);
        private bool _isPlaceholder = true;
        private const string PlaceholderText = "https://exemplo.com.br\nhttps://outro-sistema.gov.br\nhttps://app.meudominio.com";

        public UrlListForm()
        {
            InitializeComponent();

            // Placeholder
            txtUrls.Text = PlaceholderText;
            txtUrls.ForeColor = _placeholderColor;
            _isPlaceholder = true;

            txtUrls.GotFocus += (s, e) =>
            {
                if (_isPlaceholder)
                {
                    txtUrls.Text = "";
                    txtUrls.ForeColor = _textColor;
                    _isPlaceholder = false;
                }
            };

            txtUrls.LostFocus += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(txtUrls.Text))
                {
                    txtUrls.Text = PlaceholderText;
                    txtUrls.ForeColor = _placeholderColor;
                    _isPlaceholder = true;
                    UpdateCount();
                }
            };

            // Contagem em tempo real
            txtUrls.TextChanged += (s, e) => UpdateCount();
        }

        private void UpdateCount()
        {
            if (_isPlaceholder)
            {
                lblCount.Text = "0 URLs detectadas";
                return;
            }

            int count = txtUrls.Text
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Count(l => !string.IsNullOrWhiteSpace(l));

            lblCount.Text = count == 1 ? "1 URL detectada" : $"{count} URLs detectadas";
        }

        private void btnOk_Click(object sender, EventArgs e)
        {
            if (_isPlaceholder)
                txtUrls.Text = "";

            DialogResult = DialogResult.OK;
            Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
            Close();
        }
    }
}

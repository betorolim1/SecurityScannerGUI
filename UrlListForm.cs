using System;
using System.Windows.Forms;

namespace SecurityHeaderScannerGUI
{
    public partial class UrlListForm : Form
    {
        public string UrlsText => txtUrls.Text;

        public UrlListForm()
        {
            InitializeComponent();
        }

        private void btnOk_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
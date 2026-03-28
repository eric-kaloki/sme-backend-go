package resend

import (
	"log"

	"github.com/resend/resend-go/v2"
)

type Mailer struct {
	client      *resend.Client
	enabled     bool
	fromAddress string
}

func NewMailer(apiKey string, enabled bool, fromEmail, fromName string) *Mailer {
	return &Mailer{
		client:      resend.NewClient(apiKey),
		enabled:     enabled,
		fromAddress: fromName + " <" + fromEmail + ">",
	}
}

func (m *Mailer) SendUserCredentials(toEmail, firstName, lastName, username, tempPassword, role string) {
	if !m.enabled {
		log.Printf("[MAIL-DEBUG] Would send credentials to %s: User: %s, Pass: %s (Resend Disabled)", toEmail, username, tempPassword)
		return
	}

	htmlContent := `
	<html>
	<body>
		<h2>Welcome to Machakos County SME System, ` + firstName + ` ` + lastName + `!</h2>
		<p>Your account has been created with the role of <b>` + role + `</b>.</p>
		<p>Here are your temporary login credentials:</p>
		<ul>
			<li><b>Username:</b> ` + username + `</li>
			<li><b>Password:</b> ` + tempPassword + `</li>
		</ul>
		<p>Please log in and change your password immediately.</p>
	</body>
	</html>`

	go func() {
		params := &resend.SendEmailRequest{
			From:    m.fromAddress,
			To:      []string{toEmail},
			Subject: "Your Account Credentials - Machakos County SME System",
			Html:    htmlContent,
		}

		if _, err := m.client.Emails.Send(params); err != nil {
			log.Printf("ERROR: Failed to send user credentials via Resend: %v", err)
		}
	}()
}

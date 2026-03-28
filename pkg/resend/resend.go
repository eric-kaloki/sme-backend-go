package resend

import (
	"github.com/resend/resend-go/v2"
	"log"
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

// wrapHTML applies a consistent, premium design theme to all emails
func wrapHTML(title, content string) string {
	return `
	<!DOCTYPE html>
	<html>
	<head>
		<style>
			body { font-family: 'Inter', Helvetica, Arial, sans-serif; background-color: #f9fafb; color: #111827; margin: 0; padding: 20px; }
			.container { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 32px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); border-top: 4px solid #0056b3; }
			h2 { color: #0056b3; font-size: 24px; margin-bottom: 24px; }
			p { font-size: 16px; line-height: 1.5; color: #374151; margin-bottom: 16px; }
			.btn { display: inline-block; background-color: #0056b3; color: #ffffff !important; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0; }
			.footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; text-align: center; }
		</style>
	</head>
	<body>
		<div class="container">
			<h2>` + title + `</h2>
			` + content + `
			<div class="footer">
				&copy; 2026 Machakos County Government. All rights reserved.
			</div>
		</div>
	</body>
	</html>`
}

func (m *Mailer) SendUserCredentials(toEmail, firstName, lastName, username, tempPassword, role string) {
	if !m.enabled {
		return
	}
	content := `
		<p>Hi ` + firstName + ` ` + lastName + `,</p>
		<p>Your account for the Machakos County SME System has been created successfully with the role of <strong>` + role + `</strong>.</p>
		<div style="background-color: #f3f4f6; padding: 16px; border-radius: 8px; margin: 20px 0;">
			<p style="margin: 0 0 8px 0;"><strong>Username:</strong> ` + username + `</p>
			<p style="margin: 0;"><strong>Password:</strong> ` + tempPassword + `</p>
		</div>
		<p>Please log in and construct a new password immediately for security purposes.</p>
		<a href="https://machakoscountysmes-new.vercel.app/login" class="btn">Log In Now</a>
	`
	m.sendRawEmail(toEmail, "Welcome to Machakos County SME System", wrapHTML("Welcome!", content))
}

func (m *Mailer) SendPasswordReset(toEmail, firstName, resetLink string) {
	if !m.enabled {
		return
	}
	content := `
		<p>Hi ` + firstName + `,</p>
		<p>We received a request to reset the password for your Machakos County SME System account.</p>
		<p>If you made this request, click the button below to set a new password. This link will safely expire in 1 hour.</p>
		<a href="` + resetLink + `" class="btn">Reset Password</a>
		<p style="margin-top: 24px; font-size: 14px; color: #6b7280;">If you didn't request a password reset, you can safely ignore this email.</p>
	`
	m.sendRawEmail(toEmail, "Reset Your Password - Machakos County SME System", wrapHTML("Password Reset Request", content))
}

func (m *Mailer) sendRawEmail(toEmail, subject, htmlContent string) {
	go func() {
		params := &resend.SendEmailRequest{From: m.fromAddress, To: []string{toEmail}, Subject: subject, Html: htmlContent}
		if _, err := m.client.Emails.Send(params); err != nil {
			log.Printf("ERROR: Failed to send Resend email to %s: %v", toEmail, err)
		}
	}()
}

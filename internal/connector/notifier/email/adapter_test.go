package email

import (
	"context"
	"testing"
)

func TestNotifierAdapter_Channel(t *testing.T) {
	connector := New(&Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "test@example.com",
	}, nil)
	adapter := NewNotifierAdapter(connector)

	if adapter.Channel() != "Email" {
		t.Errorf("expected channel 'Email', got '%s'", adapter.Channel())
	}
}

func TestNotifierAdapter_Send_EmptyRecipient(t *testing.T) {
	connector := New(&Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "test@example.com",
	}, nil)
	adapter := NewNotifierAdapter(connector)

	err := adapter.Send(context.Background(), "", "test subject", "test body")
	if err == nil {
		t.Fatal("expected error for empty recipient")
	}
}

func TestNotifierAdapter_SendHTML_EmptyRecipient(t *testing.T) {
	connector := New(&Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "test@example.com",
	}, nil)
	adapter := NewNotifierAdapter(connector)

	err := adapter.SendHTML(context.Background(), "", "test subject", "<html>test</html>")
	if err == nil {
		t.Fatal("expected error for empty recipient")
	}
}

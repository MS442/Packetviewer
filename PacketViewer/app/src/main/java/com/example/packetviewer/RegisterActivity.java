package com.example.packetviewer;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.firebase.auth.FirebaseAuth;

public class RegisterActivity extends AppCompatActivity {

    private EditText regEmailEditText, regPasswordEditText;
    private FirebaseAuth mAuth;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register);

        mAuth = FirebaseAuth.getInstance();

        regEmailEditText = findViewById(R.id.regEmailEditText);
        regPasswordEditText = findViewById(R.id.regPasswordEditText);
        Button registerButton = findViewById(R.id.registerButton);
        TextView backToLoginTextView = findViewById(R.id.backToLoginTextView);

        registerButton.setOnClickListener(v -> registerUser());

        backToLoginTextView.setOnClickListener(v -> finish());
    }

    private void registerUser() {
        String email = regEmailEditText.getText().toString().trim();
        String password = regPasswordEditText.getText().toString().trim();

        if (email.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, "Please enter email and password", Toast.LENGTH_SHORT).show();
            return;
        }
        
        if (password.length() < 6) {
            Toast.makeText(this, "Password must be at least 6 characters", Toast.LENGTH_SHORT).show();
            return;
        }

        mAuth.createUserWithEmailAndPassword(email, password)
                .addOnCompleteListener(this, task -> {
                    if (task.isSuccessful()) {
                        Toast.makeText(RegisterActivity.this, "Registration Successful", Toast.LENGTH_SHORT).show();
                        startActivity(new Intent(RegisterActivity.this, MainActivity.class));
                        finishAffinity(); // Close all activities and go to main
                    } else {
                        String errorMsg = task.getException() != null ? task.getException().getMessage() : "Registration Failed.";
                        Toast.makeText(RegisterActivity.this, "Registration Failed: " + errorMsg, Toast.LENGTH_LONG).show();
                    }
                });
    }
}

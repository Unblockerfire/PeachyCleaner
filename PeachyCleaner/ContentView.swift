//  Created by Carson Livezey on 11/21/25.
 //
 
 import SwiftUI
 
 struct ContentView: View {
+   @State private var profile = UserProfile()
+    @State private var step: OnboardingStep = .profile
+    @State private var showEmailSheet = false
+    @State private var alertMessage: String?
+
     var body: some View {
-        VStack {
-            Image(systemName: "globe")
-                .imageScale(.large)
-                .foregroundStyle(.tint)
-            Text("Hello, world!")
+        NavigationStack {
+            VStack(alignment: .leading, spacing: 24) {
+                stepHeader
+
+                switch step {
+                case .profile:
+                    ProfileStepView(profile: $profile)
+                case .access:
+                    AccessLevelStepView(selection: $profile.accessLevel)
+                case .auth:
+                    AuthStepView(
+                        profile: profile,
+                        onGoogleTap: handleGoogleTap,
+                        onEmailTap: { showEmailSheet = true },
+                        onGuestTap: { alertMessage = "Continuing as guest. You can upgrade later." }
+                    )
+                }
+
+                Spacer()
+
+                stepControls
+            }
+            .padding(24)
+            .navigationTitle("Get Started")
+            .sheet(isPresented: $showEmailSheet) {
+                EmailSignInSheet { credentials in
+                    alertMessage = "Signed in as \(credentials.email) with password length \(credentials.password.count)."
+                }
+            }
+            .alert(item: $alertMessage) { message in
+                Alert(title: Text("Notice"), message: Text(message), dismissButton: .default(Text("OK")))
+            }
+        }
+    }
+
+    private var stepHeader: some View {
+        VStack(alignment: .leading, spacing: 8) {
+            Text(step.title)
+                .font(.largeTitle).bold()
+            Text(step.subtitle)
+                .font(.subheadline)
+                .foregroundStyle(.secondary)
+            ProgressView(value: step.progress)
+                .tint(.accentColor)
+        }
+    }
+
+    private var stepControls: some View {
+        HStack {
+            if step != .profile {
+                Button("Back") { step = step.previous }
+            }
+            Spacer()
+            Button(step == .auth ? "Finish" : "Continue", action: advanceStep)
+                .buttonStyle(.borderedProminent)
+                .disabled(!step.canAdvance(with: profile))
+        }
+    }
+
+    private func advanceStep() {
+        switch step {
+        case .profile:
+            guard !profile.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
+            step = .access
+        case .access:
+            step = .auth
+        case .auth:
+            alertMessage = "Setup complete for \(profile.name.isEmpty ? "Guest" : profile.name)."
+        }
+    }
+
+    private func handleGoogleTap() {
+        alertMessage = "Google Sign-In is currently unavailable. Please use email or continue as guest."
+    }
+}
+
+// MARK: - Supporting Types
+
+private enum OnboardingStep: CaseIterable {
+    case profile
+    case access
+    case auth
+
+    var title: String {
+        switch self {
+        case .profile: return "Tell us about you"
+        case .access: return "Choose access level"
+        case .auth: return "Sign in or continue"
+        }
+    }
+
+    var subtitle: String {
+        switch self {
+        case .profile: return "Add your name and donation preference to personalize your account."
+        case .access: return "Select how much access you need before signing in."
+        case .auth: return "Pick email sign-in or continue as a guest if Google isn't working."
+        }
+    }
+
+    var previous: OnboardingStep {
+        switch self {
+        case .profile: return .profile
+        case .access: return .profile
+        case .auth: return .access
+        }
+    }
+
+    var progress: Double {
+        switch self {
+        case .profile: return 0.33
+        case .access: return 0.66
+        case .auth: return 1.0
+        }
+    }
+
+    func canAdvance(with profile: UserProfile) -> Bool {
+        switch self {
+        case .profile:
+            !profile.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
+        case .access, .auth:
+            true
         }
-        .padding()
+    }
+}
+
+private struct UserProfile {
+    var name: String = ""
+    var donationAmount: Double = 10
+    var wantsToDonate: Bool = false
+    var accessLevel: AccessLevel = .standard
+}
+
+private enum AccessLevel: String, CaseIterable, Identifiable {
+    case guest = "Guest"
+    case standard = "Standard"
+    case admin = "Admin"
+
+    var id: String { rawValue }
+
+    var description: String {
+        switch self {
+        case .guest: return "Limited features, perfect for quick use."
+        case .standard: return "Full cleaning flow with saved preferences."
+        case .admin: return "Manage teams and donations across devices."
+        }
+    }
+}
+
+// MARK: - Step Views
+
+private struct ProfileStepView: View {
+    @Binding var profile: UserProfile
+
+    var body: some View {
+        VStack(alignment: .leading, spacing: 16) {
+            TextField("Name", text: $profile.name)
+                .textFieldStyle(.roundedBorder)
+                .submitLabel(.next)
+
+            Toggle(isOn: $profile.wantsToDonate.animation()) {
+                VStack(alignment: .leading) {
+                    Text("Add a donation?")
+                    Text("Support the team while you sign up.")
+                        .font(.caption)
+                        .foregroundStyle(.secondary)
+                }
+            }
+
+            if profile.wantsToDonate {
+                VStack(alignment: .leading) {
+                    HStack {
+                        Text("Donation: $\(Int(profile.donationAmount))")
+                            .font(.headline)
+                        Spacer()
+                    }
+                    Slider(value: $profile.donationAmount, in: 5...100, step: 5)
+                }
+                .transition(.opacity.combined(with: .move(edge: .top)))
+            }
+        }
+    }
+}
+
+private struct AccessLevelStepView: View {
+    @Binding var selection: AccessLevel
+
+    var body: some View {
+        VStack(alignment: .leading, spacing: 12) {
+            ForEach(AccessLevel.allCases) { level in
+                AccessLevelRow(level: level, isSelected: level == selection) {
+                    selection = level
+                }
+                .padding(12)
+                .background(
+                    RoundedRectangle(cornerRadius: 12)
+                        .stroke(level == selection ? Color.accentColor : Color.gray.opacity(0.3), lineWidth: 2)
+                )
+            }
+        }
+    }
+}
+
+private struct AccessLevelRow: View {
+    let level: AccessLevel
+    let isSelected: Bool
+    let action: () -> Void
+
+    var body: some View {
+        Button(action: action) {
+            HStack(alignment: .top, spacing: 12) {
+                Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
+                    .foregroundStyle(isSelected ? .accent : .secondary)
+                VStack(alignment: .leading, spacing: 4) {
+                    Text(level.rawValue)
+                        .font(.headline)
+                    Text(level.description)
+                        .font(.caption)
+                        .foregroundStyle(.secondary)
+                }
+                Spacer()
+            }
+        }
+        .buttonStyle(.plain)
+    }
+}
+
+private struct AuthStepView: View {
+    let profile: UserProfile
+    let onGoogleTap: () -> Void
+    let onEmailTap: () -> Void
+    let onGuestTap: () -> Void
+
+    var body: some View {
+        VStack(alignment: .leading, spacing: 12) {
+            Text("Choose how to continue")
+                .font(.headline)
+
+            GroupBox {
+                HStack(alignment: .top, spacing: 8) {
+                    Image(systemName: "exclamationmark.triangle.fill")
+                        .foregroundStyle(.orange)
+                    VStack(alignment: .leading, spacing: 4) {
+                        Text("Google sign-in is temporarily unavailable")
+                            .font(.subheadline).bold()
+                        Text("Use email and password or continue as a guest to keep moving.")
+                            .font(.caption)
+                            .foregroundStyle(.secondary)
+                    }
+                    Spacer()
+                }
+            }
+
+            Button(action: onGoogleTap) {
+                HStack {
+                    Image(systemName: "g.circle")
+                    Text("Sign in with Google")
+                    Spacer()
+                    Label("Unavailable", systemImage: "exclamationmark.triangle.fill")
+                        .labelStyle(.titleAndIcon)
+                        .foregroundStyle(.orange)
+                        .font(.caption)
+                }
+            }
+            .buttonStyle(.bordered)
+
+            Button(action: onEmailTap) {
+                HStack {
+                    Image(systemName: "envelope.fill")
+                    Text("Sign in with Email")
+                    Spacer()
+                }
+            }
+            .buttonStyle(.borderedProminent)
+
+            Button(action: onGuestTap) {
+                HStack {
+                    Image(systemName: "person.crop.circle.badge.questionmark")
+                    Text("Continue as Guest")
+                    Spacer()
+                }
+            }
+            .buttonStyle(.borderless)
+            .padding(.top, 4)
+
+            Divider()
+
+            VStack(alignment: .leading, spacing: 4) {
+                Text("Summary")
+                    .font(.headline)
+                Text(profileSummary)
+                    .font(.caption)
+                    .foregroundStyle(.secondary)
+            }
+        }
+    }
+
+    private var profileSummary: String {
+        let donationText = profile.wantsToDonate ? "Donation: $\(Int(profile.donationAmount))" : "No donation"
+        return "Name: \(profile.name.isEmpty ? "Guest" : profile.name) | Access: \(profile.accessLevel.rawValue) | \(donationText)"
+    }
+}
+
+private struct EmailSignInSheet: View {
+    struct Credentials {
+        let email: String
+        let password: String
+    }
+
+    @Environment(\.dismiss) private var dismiss
+    @State private var email = ""
+    @State private var password = ""
+    let onSubmit: (Credentials) -> Void
+
+    var body: some View {
+        NavigationStack {
+            Form {
+                Section(header: Text("Email")) {
+                    TextField("you@example.com", text: $email)
+                        .keyboardType(.emailAddress)
+                        .textInputAutocapitalization(.never)
+                }
+
+                Section(header: Text("Password")) {
+                    SecureField("••••••••", text: $password)
+                }
+            }
+            .navigationTitle("Email Sign-In")
+            .toolbar {
+                ToolbarItem(placement: .cancellationAction) {
+                    Button("Cancel", action: { dismiss() })
+                }
+                ToolbarItem(placement: .confirmationAction) {
+                    Button("Sign In", action: submit)
+                        .disabled(email.isEmpty || password.isEmpty)
+                }
+            }
+        }
+    }
+
+    private func submit() {
+        onSubmit(.init(email: email, password: password))
+        dismiss()
     }
 }
 
 #Preview {
     ContentView()
 }

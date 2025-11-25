//
//  PeachyCleanerApp.swift
//  PeachyCleaner
//
//  Created by Carson Livezey on 11/21/25.
//

import SwiftUI
import GoogleSignIn                         // ← REQUIRED
import GoogleSignInSwift                    // ← REQUIRED

@main
struct PeachyCleanerApp: App {

    // Your Google OAuth Client ID
    private let googleClientID = "207461181526-9k155cesoseiot03j9p3ab1qhsaailjg.apps.googleusercontent.com"

    init() {
        // Configure Google Sign-In globally
        GIDSignIn.sharedInstance.configuration =
            GIDConfiguration(clientID: googleClientID)
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                // Handles Google Sign-In redirect back into your app
                .onOpenURL { url in
                    GIDSignIn.sharedInstance.handle(url)
                }
        }
    }
}

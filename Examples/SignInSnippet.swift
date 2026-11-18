// Sample only. This file is not a Swift package target.
// Copy it into an iOS app target. The window closure runs on the main thread.

import AuthenticationServices
import Last1ID
import UIKit

final class SignInViewController: UIViewController {
    private let signIn: Last1IDSignIn
    private let nameLabel = UILabel()

    override init(nibName nibNameOrNil: String?, bundle nibBundleOrNil: Bundle?) {
        let redirect = URL(string: "https://app.example.com/auth/callback")!
        // clientID is the App ID slug, the public Client ID.
        let configuration = Last1IDConfiguration(
            clientID: "example-app",
            redirectURI: redirect,
            callback: .https(host: "app.example.com", path: "/auth/callback"),
            scopes: ["openid", "profile", "email", "offline_access", "identity_proof:read"]
        )
        let store = Last1IDKeychainTokenStore(account: configuration.clientID)
        let client = Last1IDClient(configuration: configuration, tokenStore: store)
        signIn = Last1IDSignIn(client: client)
        super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func signInTapped() async {
        do {
            let session = try await signIn.signIn {
                self.view.window ?? UIWindow()
            }
            nameLabel.text = session.claims.name ?? "Signed in"
        } catch Last1IDError.userCancelled {
            return
        } catch {
            nameLabel.text = "Sign-in failed"
        }
    }
}

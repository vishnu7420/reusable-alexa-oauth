function getUiConfig() {
    return {
        'callbacks': {
            'signInSuccess': function (user, credential, redirectUrl) {
                handleSignedInUser(user);
                return false;
            }
        },
        'signInFlow': 'popup',
        'signInOptions': [

            firebase.auth.GoogleAuthProvider.PROVIDER_ID,
            {
                provider: firebase.auth.PhoneAuthProvider.PROVIDER_ID,
                recaptchaParameters: {
                    type: 'image',
                    size: 'invisible',
                    badge: 'bottomleft'
                },
                defaultCountry: 'IN',
                defaultNationalNumber: '1234567890',
                loginHint: '+11234567890'
            },
            {
                provider: firebase.auth.EmailAuthProvider.PROVIDER_ID,
                requireDisplayName: false
            },
            firebase.auth.FacebookAuthProvider.PROVIDER_ID,
            // firebase.auth.TwitterAuthProvider.PROVIDER_ID,
            firebase.auth.GithubAuthProvider.PROVIDER_ID
        ],
        'tosUrl': 'https://www.google.com'
    };
}


// var provider = new firebase.auth.FacebookAuthProvider();

// provider.addScope('user_birthday');


// provider.setCustomParameters({
//     'display': 'popup'
// });

// firebase.auth().signInWithPopup(provider).then(function (result) {
//     // This gives you a Facebook Access Token. You can use it to access the Facebook API.
//     var token = result.credential.accessToken;
//     // The signed-in user info.
//     var user = result.user;


//     console.log(user, token)
//     // ...
// }).catch(function (error) {
//     // Handle Errors here.
//     var errorCode = error.code;
//     var errorMessage = error.message;
//     // The email of the user's account used.
//     var email = error.email;
//     // The firebase.auth.AuthCredential type that was used.
//     var credential = error.credential;
//     // ...

//     console.log(error)
// });

var ui = new firebaseui.auth.AuthUI(firebase.auth());

var handleSignedInUser = async function (user) {
    document.getElementById('user-signed-in').style.display = 'block';
    document.getElementById('user-signed-out').style.display = 'none';

    let token = await firebase.auth().currentUser.getIdToken()

    let usr = await axios.get('/reusable-api/user/profile', {
        headers: {
            'firebase': token
        }

    })

    serialize = function (obj) {
        var str = [];
        for (var p in obj)
            if (obj.hasOwnProperty(p)) {
                str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
            }
        return str.join("&");
    }
    window.location.href = "https://alexa.amazon.co.jp/api/skill/link/MNGVLK9K64KAQ" + serialize(usr.data)

    if (usr) {
        document.getElementById('phone').textContent = JSON.stringify(usr.data);

        document.getElementById('loaded').style.display = 'block';

    }
};

var handleSignedOutUser = function () {
    document.getElementById('user-signed-in').style.display = 'none';
    document.getElementById('user-signed-out').style.display = 'block';
    ui.start('#firebaseui-container', getUiConfig());
};

firebase.auth().onAuthStateChanged(function (user) {
    console.log(user)
    document.getElementById('loading').style.display = 'none';

    user ? handleSignedInUser(user) : handleSignedOutUser();
});

var initApp = function () {
    document.getElementById('sign-out').addEventListener('click', function () {
        firebase.auth().signOut();
    });
};

window.addEventListener('load', initApp);
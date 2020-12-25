import firebase_admin
from firebase_admin import messaging
from firebase_admin import credentials

cred = credentials.Certificate("instance/donelogin-9f53f-firebase-adminsdk-sxu56-8682d3b594.json")
firebase_admin.initialize_app(cred)


registration_token = 'eA0lZQ3ZSLuvlWsvWLva7I:APA91bHi1JGX3m03EfuqNMiSZzJ57vev4AT9r3RQ0vkgsORQgWM4OXIEoC6sVl8sOiGvb2zXB_LVQe_3M49JI28a6Q5T8LD_TsxE4x4FqGsFBpXECnkxmuXCbU6BQKt_K1H5MEy8d_6B'

# See documentation on defining a message payload.
notification = messaging.Notification(title = "test", body = "this is a test msg")

message = messaging.Message(
    notification = notification,
    data={
        'score': '850',
        'time': '2:45',
    },
    token=registration_token
)

# Send a message to the device corresponding to the provided
# registration token.
response = messaging.send(message)
# Response is a message ID string.
print('Successfully sent message:', response)
def save_picture(backend, user, response, *args, **kwargs):
    user.profile_pic_url = response['picture']
    user.save()
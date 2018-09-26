# Migration Plan

My data migration rule is that the first logged-in user that press `Data Migration` will get these three events.

1. I have put three events that are waiting to be migrated (Migrated1, Migrated2, and Migrated3). Initially, there three events are associated with the parent `_root_key = ndb.Key('Entities', 'root')`.

2. After the first user that press the `Migration button`, it depends on how many events are waiting to be migrated, inside the class of `Migration` will create as many events that should be migrated and make them associated with the _logged in user_. After creating these new events whose parent is the current user, delete those events that should be events. As the result, these data will only be migrated once, by the first user.

Here's the code snippet that implement the data migration:

```python
class Migration(webapp2.RequestHandler):
    def post(self):
        tok = self.request.cookies.get("s")
        session = ndb.Key("Session", tok).get()
        current_username = session.username
        user = ndb.Key("RegisteredUser", current_username).get()

        # find events that has the _root_key ancestor
        for event in ModelEvent.query(ancestor=_root_key).order(-ModelEvent.date).fetch():
            # create new events, but these new events have current user as their parent
            migrated_event = ModelEvent(
                parent=user.key, name=event.name, date=event.date)
            # put those newly created events into datastore
            migrated_event.put()
            # delete the old data which should only be migrated once
            event.key.delete()
```

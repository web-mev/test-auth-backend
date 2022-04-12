from demo.models import GlobusTokens

all_tokens = GlobusTokens.objects.all()
for t in all_tokens:
  t.delete()

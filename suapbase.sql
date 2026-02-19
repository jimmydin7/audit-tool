create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  created_at timestamp with time zone default now()
);

create table subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,

  stripe_customer_id text,
  stripe_subscription_id text,

  status text check (status in ('active', 'canceled', 'past_due')),
  current_period_end timestamp with time zone,

  created_at timestamp with time zone default now()
);

create table audits (
  id uuid primary key default gen_random_uuid(),

  user_id uuid not null
    references auth.users(id) on delete cascade,

  url text not null,

  result jsonb not null,

  created_at timestamp with time zone default now()
);

create view user_stats as
select
  u.id as user_id,
  u.email,

  -- scans this month
  count(a.id) filter (
    where a.created_at >= date_trunc('month', now())
  ) as scans_this_month,

  -- subscription status
  case
    when exists (
      select 1
      from subscriptions s
      where s.user_id = u.id
        and s.status = 'active'
    )
    then 'paid'
    else 'free'
  end as subscription_type

from profiles u
left join audits a on a.user_id = u.id
group by u.id, u.email;

create unique index subscriptions_user_id_unique on subscriptions(user_id);

ALTER TABLE profiles ADD COLUMN referred_by uuid REFERENCES auth.users(id) ON DELETE SET NULL;
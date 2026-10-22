import hashlib
from itertools import count
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.hashers import check_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from .models import *
import re
from datetime import datetime, timezone
from django.db import models as django_models
from .batch_processor import MithrilBatchProcessor
from datetime import datetime, timedelta, date
import io
from django.db.models import Count, Sum, Avg

from .crypto_utils import (
    generate_proof_id,
    generate_context_hash,
    generate_signature,
    verify_poca_signature,
)


# Create your views here.
def landing_page(request):
    # Get counts from database
    ai_agents_count = Agent.objects.filter(status='active').count()
    blockchain_tx_count = BlockchainTransaction.objects.count()
    proofs_verified = PoCAProof.objects.count()
    active_users = Users.objects.filter(is_active=True).count()
    
    # Additional stats
    total_batches = MithrilBatch.objects.count()
    
    # Use date.today() instead
    today = date.today()
    week_ago = today - timedelta(days=7)
    
    # Recent proofs for display
    recent_proofs = PoCAProof.objects.select_related('agent', 'submitted_by').order_by('-created_at')[:5]
    
    # Recent transactions - use prefetch_related for many-to-many
    recent_transactions = BlockchainTransaction.objects.select_related('related_batch').prefetch_related('related_agents').order_by('-created_at')[:5]
    
    # Use date.today() for filters
    proofs_today = PoCAProof.objects.filter(created_at__date=today).count()
    proofs_this_week = PoCAProof.objects.filter(created_at__date__gte=week_ago).count()
    
    context = {
        'ai_agents_count': ai_agents_count,
        'blockchain_tx_count': blockchain_tx_count,
        'proofs_verified': proofs_verified,
        'active_users': active_users,
        'total_batches': total_batches,
        'recent_proofs': recent_proofs,
        'recent_transactions': recent_transactions,
        'proofs_today': proofs_today,
        'proofs_this_week': proofs_this_week,
    }
    
    return render(request, 'index.html', context)


def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        # role = request.POST.get('role', 'user')
        
        role = 'user'
        errors = []
        
        if not username:
            errors.append('Username is required')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username can only contain letters, numbers, and underscores')
        
        if not email:
            errors.append('Email is required')
        else:
            try:
                validate_email(email)
            except ValidationError:
                errors.append('Invalid email address')
        
        if not password:
            errors.append('Password is required')
        elif len(password) < 8:
            errors.append('Password must be at least 8 characters')
        elif not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        elif not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        elif not re.search(r'\d', password):
            errors.append('Password must contain at least one number')
        
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if role not in ['admin', 'user']:
            errors.append('Invalid role selected')
        
        if errors:
            for error in errors:
                messages.error(request, error)
            return redirect('index')
        
        if Users.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists. Please choose another.')
            return redirect('index')
        
        if Users.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered. Please login or use another email.')
            return redirect('index')
        
        try:
            user = Users(
                username=username,
                email=email,
                role=role,
                is_active=True
            )
            user.set_password(password)
            user.save()
            
            # # Store user in session
            # request.session['user_id'] = user.id
            # request.session['username'] = user.username
            # request.session['role'] = user.role
            # request.session['is_authenticated'] = True
            
            # messages.success(request, f'Registration successful! Welcome {username}!')
            
            # if role == 'admin':
            #     return redirect('admin_dashboard')
            # else:
            #     return redirect('user_dashboard')
                
        except IntegrityError as e:
            messages.error(request, 'An error occurred during registration. Please try again.')
            return redirect('index')
        except Exception as e:
            messages.error(request, 'Unexpected error occurred. Please try again.')
            return redirect('index')
    
    return redirect('index')


def get_or_create_default_admin():
    try:
        admin_user = Users.objects.get(username='Admin_123')
        
        if not admin_user.check_password('Admin@123'):
            admin_user.set_password('Admin@123')
            admin_user.save()
            
        return admin_user
    except Users.DoesNotExist:
        admin_user = Users(
            username='Admin_123',
            email='admin@secureai.com',
            role='admin',
            is_active=True
        )
        admin_user.set_password('Admin@123')
        admin_user.save()
        return admin_user


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        # Validation
        if not username:
            messages.error(request, 'Username is required')
            return redirect('index')
        
        if not password:
            messages.error(request, 'Password is required')
            return redirect('index')
        
        try:
            if username == 'Admin_123' and password == 'Admin@123':
                admin_user = get_or_create_default_admin()
                
                request.session['user_id'] = admin_user.id
                request.session['username'] = admin_user.username
                request.session['role'] = admin_user.role
                request.session['is_authenticated'] = True
                
                messages.success(request, f'Welcome back, {admin_user.username}!')
                return redirect('admin_dashboard')
            
            user = Users.objects.get(username=username)
            
            if not user.is_active:
                messages.error(request, 'Account is disabled. Contact administrator.')
                return redirect('index')
            
            if user.check_password(password):
                request.session['user_id'] = user.id
                request.session['username'] = user.username
                request.session['role'] = user.role
                request.session['is_authenticated'] = True
                
                messages.success(request, f'Welcome back, {user.username}!')
                
                if user.role == 'admin':
                    return redirect('admin_dashboard')
                else:
                    return redirect('user_dashboard')
            else:
                messages.error(request, 'Invalid password. Please try again.')
                return redirect('index')
                
        except Users.DoesNotExist:
            messages.error(request, 'Username not found. Please check your username or register.')
            return redirect('index')
        except Exception as e:
            messages.error(request, 'An error occurred during login. Please try again.')
            return redirect('index')
    
    return redirect('index')


def logout_view(request):
    username = request.session.get('username', 'User')
    request.session.flush()
    messages.success(request, f'Goodbye {username}! You have been logged out successfully.')
    return redirect('index')


def admin_dashboard_view(request):
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # ============ STATS ============
    total_agents = Agent.objects.count()
    active_agents = Agent.objects.filter(status='active').count()
    
    total_proofs = PoCAProof.objects.count()
    batched_proofs = PoCAProof.objects.filter(is_batched=True).count()
    
    total_batches = MithrilBatch.objects.count()
    anchored_batches = MithrilBatch.objects.filter(status='anchored').count()
    
    total_transactions = BlockchainTransaction.objects.count()
    
    # ============ RECENT AGENTS ============
    recent_agents = Agent.objects.all().order_by('-created_at')[:5]
    
    # ============ RECENT TRANSACTIONS ============
    recent_transactions = BlockchainTransaction.objects.all().order_by('-created_at')[:5]
    
    # ============ CHART DATA (Last 7 days) ============
    from datetime import datetime, timedelta
    import calendar
    
    # Get last 7 days
    today = datetime.now().date()
    day_names = []
    proof_counts = []
    tx_counts = []
    
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        day_names.append(date.strftime('%a'))
        
        # Count proofs for this day
        proof_count = PoCAProof.objects.filter(
            created_at__date=date
        ).count()
        proof_counts.append(proof_count)
        
        # Count transactions for this day
        tx_count = BlockchainTransaction.objects.filter(
            created_at__date=date
        ).count()
        tx_counts.append(tx_count)
    
    # ============ RECENT ACTIVITY (Dynamic) ============
    recent_activity = []
    
    # Get recent agents
    for agent in recent_agents[:2]:
        recent_activity.append({
            'icon': 'fa-check-circle',
            'icon_color': '#34d399',
            'icon_bg': 'rgba(52, 211, 153, 0.15)',
            'title': 'New Agent Registered',
            'desc': f'{agent.name} ({agent.agent_id}) was registered successfully',
            'time': agent.created_at
        })
    
    # Get recent batches
    recent_batches = MithrilBatch.objects.filter(status='anchored').order_by('-anchored_at')[:2]
    for batch in recent_batches:
        recent_activity.append({
            'icon': 'fa-tree',
            'icon_color': '#fbbf24',
            'icon_bg': 'rgba(251, 191, 36, 0.15)',
            'title': 'Batch Anchored on Blockchain',
            'desc': f'{batch.batch_id} with {batch.num_proofs} proofs anchored on Ganache (Block #{batch.block_number or "N/A"})',
            'time': batch.anchored_at or batch.created_at
        })
    
    # Get recent users
    recent_users = Users.objects.filter(is_active=True).order_by('-created_at')[:2]
    for u in recent_users:
        recent_activity.append({
            'icon': 'fa-user-plus',
            'icon_color': '#60a5fa',
            'icon_bg': 'rgba(96, 165, 250, 0.15)',
            'title': 'New User Registration',
            'desc': f'{u.username} registered as {u.get_role_display()}',
            'time': u.created_at
        })
    
    # Get recent proofs
    recent_proofs = PoCAProof.objects.filter(safety_score__gte=0.7).order_by('-created_at')[:2]
    for proof in recent_proofs:
        recent_activity.append({
            'icon': 'fa-fingerprint',
            'icon_color': '#a78bfa',
            'icon_bg': 'rgba(167, 139, 250, 0.15)',
            'title': 'PoCA Proof Generated',
            'desc': f'{proof.proof_id} generated with safety score {proof.safety_score:.2f}',
            'time': proof.created_at
        })
    
    # Sort activity by time (newest first) and limit to 5
    recent_activity.sort(key=lambda x: x['time'], reverse=True)
    recent_activity = recent_activity[:5]
    
    context = {
        'user': user,
        'total_agents': total_agents,
        'active_agents': active_agents,
        'total_proofs': total_proofs,
        'batched_proofs': batched_proofs,
        'total_batches': total_batches,
        'anchored_batches': anchored_batches,
        'total_transactions': total_transactions,
        'recent_agents': recent_agents,
        'recent_transactions': recent_transactions,
        'day_names': day_names,
        'proof_counts': proof_counts,
        'tx_counts': tx_counts,
        'recent_activity': recent_activity,
    }
    
    return render(request, 'admin/dashboard.html', context)


from .blockchain.logic import *
from .crypto_utils import *
def agents_list_view(request):
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get filters
    search = request.GET.get('search', '')
    provider = request.GET.get('provider', '')
    status = request.GET.get('status', '')
    blockchain = request.GET.get('blockchain', '')
    
    # Build queryset
    agents = Agent.objects.all()
    
    if search:
        agents = agents.filter(
            models.Q(name__icontains=search) | 
            models.Q(agent_id__icontains=search) |
            models.Q(did__icontains=search)
        )
    if provider:
        agents = agents.filter(llm_provider=provider)
    if status:
        agents = agents.filter(status=status)
    if blockchain == 'registered':
        agents = agents.filter(registration_tx_hash__isnull=False)
    elif blockchain == 'unregistered':
        agents = agents.filter(registration_tx_hash__isnull=True)
    
    agents = agents.order_by('-created_at')
    
    # Calculate stats for the template
    total_agents = agents.count()
    active_agents = agents.filter(status='active').count()
    inactive_agents = agents.filter(status='inactive').count()
    onchain_agents = agents.filter(registration_tx_hash__isnull=False).count()
    
    context = {
        'user': user,
        'agents': agents,
        'total_agents': total_agents,
        'active_agents': active_agents,
        'inactive_agents': inactive_agents,
        'onchain_agents': onchain_agents,
    }
    
    return render(request, 'admin/agents_list.html', context)



def add_agent_view(request):
    if request.method != 'POST':
        return redirect('agents_list')
    
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to perform this action.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get form data
    name = request.POST.get('name', '').strip()
    description = request.POST.get('description', '').strip()
    llm_provider = request.POST.get('llm_provider', '').strip()
    model_name = request.POST.get('model_name', '').strip()
    api_key = request.POST.get('api_key', '').strip()
    
    # Validation
    if not all([name, llm_provider, model_name, api_key]):
        messages.error(request, 'All required fields must be filled.')
        return redirect('agents_list')
    
    try:
        # Generate keys and IDs
        private_key, public_key = generate_keypair()
        did = generate_did(public_key)
        model_hash = generate_model_hash(llm_provider, model_name)
        agent_id = generate_agent_id()
        
        # Create agent
        agent = Agent(
            agent_id=agent_id,
            name=name,
            description=description,
            llm_provider=llm_provider,
            model_name=model_name,
            api_key_encrypted=encrypt_value(api_key),
            did=did,
            public_key=public_key,
            private_key_encrypted=encrypt_value(private_key),
            model_hash=model_hash,
            registered_by=user,
            status='active',
        )
        agent.save()
        
        # Register on blockchain
        # result = addNewData({
        #     "type": "agent_registration",
        #     "agent_id": agent_id,
        #     "did": did,
        #     "public_key": public_key,
        #     "model_hash": model_hash,
        # })
        # print(result, retrieveData())
        # if result == "Success":
        #     # Update with transaction hash (you'll get this from blockchain)
        #     agent.registration_tx_hash = f"0x{hashlib.sha256(f'{agent_id}{did}'.encode()).hexdigest()[:40]}"
        #     agent.save()
        #     messages.success(request, f'Agent "{name}" registered and anchored on blockchain!')
        # else:
        #     messages.warning(request, f'Agent "{name}" saved, but blockchain write failed: {result}')
        
        result = addNewData({
            "type": "agent_registration",
            "agent_id": agent_id,
            "did": did,
            "public_key": public_key,
            "model_hash": model_hash,
        })
        
        if result["success"]:
            agent.registration_tx_hash = result["tx_hash"]
            agent.save()
            messages.success(request, f'Agent "{name}" registered and anchored on blockchain! Tx: {result["tx_hash"][:16]}...')
        else:
            messages.warning(request, f'Agent "{name}" saved, but blockchain write failed: {result.get("error")}')
        
    except Exception as e:
        messages.error(request, f'Error creating agent: {str(e)}')
    
    return redirect('agents_list')


def edit_agent_view(request, agent_id):
    if request.method != 'POST':
        return redirect('agents_list')
    
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to perform this action.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    agent = get_object_or_404(Agent, id=agent_id)
    
    # Get form data
    name = request.POST.get('name', '').strip()
    llm_provider = request.POST.get('llm_provider', '').strip()
    model_name = request.POST.get('model_name', '').strip()
    api_key = request.POST.get('api_key', '').strip()
    description = request.POST.get('description', '').strip()
    status = request.POST.get('status', 'active')
    
    if not all([name, llm_provider, model_name]):
        messages.error(request, 'Name, provider, and model are required.')
        return redirect('agents_list')
    
    try:
        # Update agent
        agent.name = name
        agent.llm_provider = llm_provider
        agent.model_name = model_name
        agent.description = description
        agent.status = status
        
        # Update API key if provided
        if api_key:
            agent.api_key_encrypted = encrypt_value(api_key)
        
        agent.save()
        messages.success(request, f'Agent "{name}" updated successfully!')
        
    except Exception as e:
        messages.error(request, f'Error updating agent: {str(e)}')
    
    return redirect('agents_list')


def delete_agent_view(request, agent_id):
    if request.method != 'POST':
        return redirect('agents_list')
    
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to perform this action.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    agent = get_object_or_404(Agent, id=agent_id)
    agent_name = agent.name
    agent_id_display = agent.agent_id
    
    try:
        # Check if agent has proofs
        proof_count = agent.proofs.count()
        if proof_count > 0:
            messages.warning(request, f'Agent has {proof_count} associated proofs. Delete them first.')
            return redirect('agents_list')
        
        agent.delete()
        messages.success(request, f'Agent "{agent_name}" deleted successfully!')
        
    except Exception as e:
        messages.error(request, f'Error deleting agent: {str(e)}')
    
    return redirect('agents_list')


def users_list_view(request):
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    
    try:
        admin_user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if admin_user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get filters
    search = request.GET.get('search', '')
    role = request.GET.get('role', '')
    status = request.GET.get('status', '')
    
    # Build queryset
    users = Users.objects.all()
    
    if search:
        users = users.filter(
            django_models.Q(username__icontains=search) | 
            django_models.Q(email__icontains=search)
        )
    if role:
        users = users.filter(role=role)
    if status == 'active':
        users = users.filter(is_active=True)
    elif status == 'inactive':
        users = users.filter(is_active=False)
    
    users = users.order_by('-created_at')
    
    # Calculate stats
    total_users = users.count()
    active_users = Users.objects.filter(is_active=True).count()
    inactive_users = Users.objects.filter(is_active=False).count()
    admin_count = Users.objects.filter(role='admin').count()
    
    context = {
        'admin_user': admin_user,
        'users': users,
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'admin_count': admin_count,
    }
    
    return render(request, 'admin/users_list.html', context)


def add_user_view(request):
    if request.method != 'POST':
        return redirect('users_list')
    
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to perform this action.')
        return redirect('index')
    
    try:
        admin_user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if admin_user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get form data
    username = request.POST.get('username', '').strip()
    email = request.POST.get('email', '').strip()
    role = request.POST.get('role', 'user')
    password = request.POST.get('password', '')
    confirm_password = request.POST.get('confirm_password', '')
    
    # Validation
    errors = []
    
    if not username:
        errors.append('Username is required')
    elif len(username) < 3:
        errors.append('Username must be at least 3 characters')
    elif not re.match(r'^[a-zA-Z0-9_]+$', username):
        errors.append('Username can only contain letters, numbers, and underscores')
    
    if not email:
        errors.append('Email is required')
    else:
        try:
            validate_email(email)
        except ValidationError:
            errors.append('Invalid email address')
    
    if not password:
        errors.append('Password is required')
    elif len(password) < 8:
        errors.append('Password must be at least 8 characters')
    elif not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')
    elif not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')
    elif not re.search(r'\d', password):
        errors.append('Password must contain at least one number')
    
    if password != confirm_password:
        errors.append('Passwords do not match')
    
    if errors:
        for error in errors:
            messages.error(request, error)
        return redirect('users_list')
    
    # Check if username or email exists
    if Users.objects.filter(username=username).exists():
        messages.error(request, 'Username already exists.')
        return redirect('users_list')
    
    if Users.objects.filter(email=email).exists():
        messages.error(request, 'Email already registered.')
        return redirect('users_list')
    
    try:
        user = Users(
            username=username,
            email=email,
            role=role,
            is_active=True
        )
        user.set_password(password)
        user.save()
        
        messages.success(request, f'User "{username}" added successfully!')
        
    except IntegrityError:
        messages.error(request, 'An error occurred. Please try again.')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
    
    return redirect('users_list')


def edit_user_view(request, user_id):
    if request.method != 'POST':
        return redirect('users_list')
    
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to perform this action.')
        return redirect('index')
    
    try:
        admin_user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if admin_user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    user = get_object_or_404(Users, id=user_id)
    
    # Can't edit yourself through this form
    if user.id == admin_user.id:
        messages.error(request, 'You cannot edit your own account through this form.')
        return redirect('users_list')
    
    # Get form data
    username = request.POST.get('username', '').strip()
    email = request.POST.get('email', '').strip()
    role = request.POST.get('role', 'user')
    password = request.POST.get('password', '')
    
    # Validation
    errors = []
    
    if not username:
        errors.append('Username is required')
    elif len(username) < 3:
        errors.append('Username must be at least 3 characters')
    elif not re.match(r'^[a-zA-Z0-9_]+$', username):
        errors.append('Username can only contain letters, numbers, and underscores')
    
    if not email:
        errors.append('Email is required')
    else:
        try:
            validate_email(email)
        except ValidationError:
            errors.append('Invalid email address')
    
    if errors:
        for error in errors:
            messages.error(request, error)
        return redirect('users_list')
    
    # Check if username or email exists for other users
    if Users.objects.filter(username=username).exclude(id=user.id).exists():
        messages.error(request, 'Username already taken by another user.')
        return redirect('users_list')
    
    if Users.objects.filter(email=email).exclude(id=user.id).exists():
        messages.error(request, 'Email already used by another user.')
        return redirect('users_list')
    
    try:
        user.username = username
        user.email = email
        user.role = role
        
        if password:  # Only update password if provided
            if len(password) < 8:
                messages.error(request, 'Password must be at least 8 characters.')
                return redirect('users_list')
            user.set_password(password)
        
        user.save()
        messages.success(request, f'User "{username}" updated successfully!')
        
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
    
    return redirect('users_list')


def toggle_user_view(request, user_id):
    if request.method != 'POST':
        return redirect('users_list')
    
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to perform this action.')
        return redirect('index')
    
    try:
        admin_user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if admin_user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    user = get_object_or_404(Users, id=user_id)
    
    # Can't toggle yourself
    if user.id == admin_user.id:
        messages.error(request, 'You cannot deactivate your own account.')
        return redirect('users_list')
    
    try:
        user.is_active = not user.is_active
        user.save()
        
        status = 'activated' if user.is_active else 'deactivated'
        messages.success(request, f'User "{user.username}" {status} successfully!')
        
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
    
    return redirect('users_list')


def delete_user_view(request, user_id):
    if request.method != 'POST':
        return redirect('users_list')
    
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to perform this action.')
        return redirect('index')
    
    try:
        admin_user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if admin_user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    user = get_object_or_404(Users, id=user_id)
    
    # Can't delete yourself
    if user.id == admin_user.id:
        messages.error(request, 'You cannot delete your own account.')
        return redirect('users_list')
    
    username = user.username
    
    try:
        user.delete()
        messages.success(request, f'User "{username}" deleted successfully!')
        
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
    
    return redirect('users_list')


def poca_proofs_view(request):
    # PoCA Proofs management page with dynamic data from database
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get filter parameters
    search = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '')
    agent_filter = request.GET.get('agent', '')
    
    # Base queryset
    proofs = PoCAProof.objects.all().select_related('agent', 'submitted_by', 'batch')
    
    # Apply filters
    if search:
        proofs = proofs.filter(
            django_models.Q(proof_id__icontains=search) |
            django_models.Q(query_text__icontains=search) |
            django_models.Q(agent__name__icontains=search)
        )
    
    if status_filter:
        if status_filter == 'batched':
            proofs = proofs.filter(is_batched=True)
        elif status_filter == 'pending':
            proofs = proofs.filter(is_batched=False)
        elif status_filter == 'anchored':
            proofs = proofs.filter(is_batched=True, batch__status='anchored')
        elif status_filter == 'failed':
            proofs = proofs.filter(safety_score__lt=0.5)
    
    if agent_filter:
        proofs = proofs.filter(agent__id=agent_filter)
    
    # Order by newest first
    proofs = proofs.order_by('-created_at')
    
    # ============ PAGINATION ============
    from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
    
    # Paginate - 10 records per page
    paginator = Paginator(proofs, 10)
    page_number = request.GET.get('page')
    
    try:
        page_obj = paginator.get_page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.get_page(1)
    except EmptyPage:
        page_obj = paginator.get_page(paginator.num_pages)
    
    # Calculate stats (using the full queryset, not paginated)
    total_proofs = PoCAProof.objects.count()
    batched_proofs = PoCAProof.objects.filter(is_batched=True).count()
    pending_proofs = PoCAProof.objects.filter(is_batched=False).count()
    
    # Calculate verification success rate
    successful_proofs = PoCAProof.objects.filter(safety_score__gte=0.7).count()
    verification_rate = round((successful_proofs / total_proofs * 100) if total_proofs > 0 else 0, 1)
    
    # Get all agents for filter dropdown
    agents = Agent.objects.filter(status='active').order_by('name')
    
    # Prepare proof data for the current page
    proof_data = []
    for proof in page_obj:
        if proof.is_batched:
            status = 'batched'
            status_display = 'Batched'
        else:
            status = 'pending'
            status_display = 'Pending'
        
        if proof.safety_score >= 0.7:
            safety_class = 'high'
        elif proof.safety_score >= 0.4:
            safety_class = 'medium'
        else:
            safety_class = 'low'
        
        # Get transaction hash if proof is batched and has a batch
        tx_hash = 'Pending'
        block_number = '—'
        if proof.batch:
            from app.models import BlockchainTransaction
            blockchain_tx = BlockchainTransaction.objects.filter(related_batch=proof.batch).order_by('-created_at').first()
            if blockchain_tx:
                tx_hash = blockchain_tx.tx_hash
                block_number = blockchain_tx.block_number if blockchain_tx.block_number else '—'
            elif proof.batch.anchored_at:
                tx_hash = 'Anchored (Tx Pending)'
        
        proof_data.append({
            'proof': proof,
            'status': status,
            'status_display': status_display,
            'safety_class': safety_class,
            'safety_percent': round(proof.safety_score * 100, 1),
            'batch_id': proof.batch.batch_id if proof.batch else None,
            'agent_did': proof.agent.did if proof.agent.did else 'N/A',
            'tx_hash': tx_hash,
            'block_number': block_number,
        })
    
    context = {
        'user': user,
        'proofs': proof_data,
        'page_obj': page_obj,
        'paginator': paginator,
        'total_proofs': total_proofs,
        'batched_proofs': batched_proofs,
        'pending_proofs': pending_proofs,
        'verification_rate': verification_rate,
        'agents': agents,
        'search': search,
        'status_filter': status_filter,
        'agent_filter': agent_filter,
    }
    
    return render(request, 'admin/poca_proofs.html', context)


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
@csrf_exempt
def delete_proof_view(request, proof_id):
    #Delete a PoCA proof (AJAX)
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})
    
    if user.role != 'admin':
        return JsonResponse({'success': False, 'message': 'Admin access required'})
    
    try:
        proof = PoCAProof.objects.get(id=proof_id)
        proof.delete()
        return JsonResponse({'success': True, 'message': 'Proof deleted successfully'})
    except PoCAProof.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Proof not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


"""
================================================================================
MITHRIL BATCHES — COMPLETE VIEWS
================================================================================
Views required by admin/mithril_batches.html:

    1. mithril_batches_view   -> GET  /mithril-batches/          (page)
    2. process_batches_view   -> POST /process-batches/          (New Batch button)
    3. anchor_batch_view      -> POST /anchor-batch/<batch_id>/  (Anchor action)
    4. retry_batch_view       -> POST /retry-batch/<batch_id>/   (Retry action)
    5. verify_batch_view      -> GET  /verify-batch/<batch_id>/  (Verify action)
    6. delete_batch_view      -> POST /delete-batch/<batch_id>/  (Delete action)

urls.py entries are at the bottom of this file.
================================================================================
"""

import json
import hashlib

from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.db import models as django_models
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.http import require_POST

from app.models import (
    Users,
    MithrilBatch,
    PoCAProof,
    BlockchainTransaction,
)


# ==============================================================================
# HELPERS
# ==============================================================================

def _admin_guard(request):
    """
    Returns (user, error_response). If error_response is not None, return it.
    """
    if not request.session.get('is_authenticated', False):
        return None, 'not_authenticated'

    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        return None, 'session_expired'

    if user.role != 'admin':
        return None, 'not_admin'

    return user, None


def _sha(a, b=None):
    """SHA-256 of one value, or of the concatenation of two."""
    data = a if b is None else (a + b)
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def build_merkle_levels(leaves):
    """
    Build every level of a Merkle tree.

    Returns a list of levels, bottom-up:
        [ [leaf, leaf, ...], [intermediate, ...], ..., [root] ]

    An odd node at the end of a level is promoted unchanged to the next level
    (the standard "carry up" rule). Returns [] for an empty leaf list.
    """
    if not leaves:
        return []

    levels = [list(leaves)]
    current = list(leaves)

    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                nxt.append(_sha(current[i], current[i + 1]))
            else:
                nxt.append(current[i])
        levels.append(nxt)
        current = nxt

    return levels


def compute_merkle_root(leaves):
    """Convenience wrapper — returns the root hash, or '' if there are no leaves."""
    levels = build_merkle_levels(leaves)
    return levels[-1][0] if levels else ''


# ==============================================================================
# 1. MAIN PAGE VIEW
# ==============================================================================

def mithril_batches_view(request):
    """Mithril Batches management page with dynamic data from the database."""

    user, err = _admin_guard(request)
    if err == 'not_authenticated':
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    if err == 'session_expired':
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    if err == 'not_admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')

    # ---------------- filters ----------------
    search = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '')
    sort = request.GET.get('sort', 'newest')

    batches = MithrilBatch.objects.all().prefetch_related('proofs__agent')

    if search:
        batches = batches.filter(
            django_models.Q(batch_id__icontains=search) |
            django_models.Q(merkle_root__icontains=search) |
            django_models.Q(tx_hash__icontains=search)
        )

    if status_filter:
        batches = batches.filter(status=status_filter)

    sort_map = {
        'newest': '-created_at',
        'oldest': 'created_at',
        'most_proofs': '-num_proofs',
        'least_proofs': 'num_proofs',
    }
    batches = batches.order_by(sort_map.get(sort, '-created_at'))

    # ---------------- pagination ----------------
    paginator = Paginator(batches, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = paginator.get_page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.get_page(1)
    except EmptyPage:
        page_obj = paginator.get_page(paginator.num_pages)

    # ---------------- stats (full queryset, not paginated) ----------------
    total_batches = MithrilBatch.objects.count()
    anchored_batches = MithrilBatch.objects.filter(status='anchored').count()
    pending_batches = MithrilBatch.objects.filter(status='pending').count()
    failed_batches = MithrilBatch.objects.filter(status='failed').count()
    total_proofs_batched = PoCAProof.objects.filter(is_batched=True).count()
    pending_proofs = PoCAProof.objects.filter(is_batched=False).count()

    # ---------------- per-batch data ----------------
    # batch_data  -> used to render the table rows
    # batches_payload -> serialised to JSON for the view modal (json_script)
    batch_data = []
    batches_payload = {}

    # Prefetch all blockchain transactions for this page in one query
    page_batch_ids = [b.pk for b in page_obj]
    tx_map = {}
    for tx in BlockchainTransaction.objects.filter(
            related_batch_id__in=page_batch_ids).order_by('created_at'):
        tx_map[tx.related_batch_id] = tx        # last one wins = newest

    for batch in page_obj:
        tx_hash = batch.tx_hash if batch.tx_hash else 'Pending'
        block_number = batch.block_number if batch.block_number else ''

        gas_used = ''
        anchored_at = None
        blockchain_tx = tx_map.get(batch.pk)
        if blockchain_tx:
            gas_used = getattr(blockchain_tx, 'gas_used', '') or ''
            anchored_at = (getattr(blockchain_tx, 'anchored_at', None)
                           or getattr(blockchain_tx, 'created_at', None))

        # ---- real proofs, in a deterministic order ----
        proofs_in_batch = list(
            batch.proofs.select_related('agent').order_by('created_at', 'pk')
        )
        actual_proofs = len(proofs_in_batch)

        # ---- unique agents, order preserved ----
        agents_info, seen = [], set()
        for proof in proofs_in_batch:
            agent = getattr(proof, 'agent', None)
            if agent and agent.name and agent.did not in seen:
                seen.add(agent.did)
                agents_info.append({
                    'name': agent.name,
                    'did': agent.did or 'N/A',
                })

        # ---- Merkle leaves = the real proof signatures ----
        leaves = [(proof.signature or 'no_sig') for proof in proofs_in_batch]
        merkle_levels = build_merkle_levels(leaves)
        computed_root = merkle_levels[-1][0] if merkle_levels else ''

        # Does the stored root match a freshly computed one?
        root_matches = bool(batch.merkle_root) and (
            computed_root == batch.merkle_root
        )

        batches_payload[batch.batch_id] = {
            'batch_id': batch.batch_id,
            'merkle_root': batch.merkle_root or '',
            'computed_root': computed_root,
            'root_matches': root_matches,
            'declared_proofs': batch.num_proofs or 0,
            'actual_proofs': actual_proofs,
            'status': batch.status or 'pending',
            'status_display': batch.get_status_display() if hasattr(batch, 'get_status_display') else (batch.status or ''),
            'tx_hash': tx_hash,
            'block_number': str(block_number),
            'gas_used': str(gas_used),
            'created': batch.created_at.strftime('%Y-%m-%d %H:%M:%S') if batch.created_at else '',
            'anchored_at': anchored_at.strftime('%Y-%m-%d %H:%M:%S') if anchored_at else 'Not anchored',
            'signature': batch.aggregated_signature or '',
            'agents': agents_info,
            'levels': merkle_levels,
        }

        batch_data.append({
            'batch': batch,
            'tx_hash': tx_hash,
            'block_number': block_number or '—',
            'gas_used': gas_used or '—',
            'anchored_at': anchored_at,
            'agents_info': agents_info,
            'agent_count': len(agents_info),
            'actual_proofs': actual_proofs,
            'proof_mismatch': actual_proofs != (batch.num_proofs or 0),
        })

    context = {
        'user': user,
        'batches': batch_data,
        'batches_json': batches_payload,
        'page_obj': page_obj,
        'paginator': paginator,
        'total_batches': total_batches,
        'anchored_batches': anchored_batches,
        'pending_batches': pending_batches,
        'failed_batches': failed_batches,
        'total_proofs_batched': total_proofs_batched,
        'pending_proofs': pending_proofs,
        'search': search,
        'status_filter': status_filter,
        'sort': sort,
    }

    return render(request, 'admin/mithril_batches.html', context)


# ==============================================================================
# 2. CREATE / PROCESS BATCH
# ==============================================================================

@require_POST
def process_batches_view(request):
    """Create a new batch from all currently un-batched proofs."""
    user, err = _admin_guard(request)
    if err:
        return JsonResponse({'success': False, 'message': 'Not authorised.'}, status=403)

    pending = list(
        PoCAProof.objects.filter(is_batched=False).order_by('created_at', 'pk')
    )
    if not pending:
        return JsonResponse({'success': False, 'message': 'No pending proofs to batch.'})

    leaves = [(p.signature or 'no_sig') for p in pending]
    root = compute_merkle_root(leaves)

    last = MithrilBatch.objects.order_by('-pk').first()
    next_num = (last.pk + 1) if last else 1
    batch_id = 'BATCH-%04d' % next_num

    batch = MithrilBatch.objects.create(
        batch_id=batch_id,
        merkle_root=root,
        num_proofs=len(pending),          # set from the real count
        status='pending',
    )

    # Attach proofs and mark them batched
    for proof in pending:
        proof.batch = batch
        proof.is_batched = True
        proof.save(update_fields=['batch', 'is_batched'])

    # Keep num_proofs honest even if something raced us
    batch.num_proofs = batch.proofs.count()
    batch.save(update_fields=['num_proofs'])

    return JsonResponse({
        'success': True,
        'message': 'Batch %s created with %d proofs.' % (batch.batch_id, batch.num_proofs),
        'batch_id': batch.batch_id,
    })


# ==============================================================================
# 3. ANCHOR BATCH
# ==============================================================================

@require_POST
def anchor_batch_view(request, batch_id):
    """Anchor a pending batch's Merkle root on-chain."""
    user, err = _admin_guard(request)
    if err:
        return JsonResponse({'success': False, 'message': 'Not authorised.'}, status=403)

    try:
        batch = MithrilBatch.objects.get(batch_id=batch_id)
    except MithrilBatch.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Batch not found.'}, status=404)

    if batch.status == 'anchored':
        return JsonResponse({'success': False, 'message': 'Batch is already anchored.'})

    try:
        # ------------------------------------------------------------------
        # Replace this block with your real blockchain call. It must return
        # a tx hash, a block number and the gas used.
        # ------------------------------------------------------------------
        from app.blockchain import anchor_merkle_root      # your own module
        result = anchor_merkle_root(batch.merkle_root)
        tx_hash = result['tx_hash']
        block_number = result['block_number']
        gas_used = result.get('gas_used')

        batch.tx_hash = tx_hash
        batch.block_number = block_number
        batch.status = 'anchored'
        batch.save(update_fields=['tx_hash', 'block_number', 'status'])

        BlockchainTransaction.objects.create(
            related_batch=batch,
            tx_hash=tx_hash,
            block_number=block_number,
            gas_used=gas_used,
        )

        return JsonResponse({
            'success': True,
            'message': 'Batch %s anchored in block #%s.' % (batch.batch_id, block_number),
        })

    except Exception as exc:
        batch.status = 'failed'
        batch.save(update_fields=['status'])
        return JsonResponse({
            'success': False,
            'message': 'Anchoring failed: %s' % exc,
        })


# ==============================================================================
# 4. RETRY BATCH
# ==============================================================================

@require_POST
def retry_batch_view(request, batch_id):
    """Reset a failed batch to pending, recompute its root, and re-anchor."""
    user, err = _admin_guard(request)
    if err:
        return JsonResponse({'success': False, 'message': 'Not authorised.'}, status=403)

    try:
        batch = MithrilBatch.objects.get(batch_id=batch_id)
    except MithrilBatch.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Batch not found.'}, status=404)

    proofs = list(batch.proofs.order_by('created_at', 'pk'))
    leaves = [(p.signature or 'no_sig') for p in proofs]

    batch.merkle_root = compute_merkle_root(leaves)
    batch.num_proofs = len(proofs)
    batch.status = 'pending'
    batch.save(update_fields=['merkle_root', 'num_proofs', 'status'])

    return JsonResponse({
        'success': True,
        'message': 'Batch %s reset to pending — root recomputed over %d proofs.'
                   % (batch.batch_id, len(proofs)),
    })


# ==============================================================================
# 5. VERIFY BATCH
# ==============================================================================

def verify_batch_view(request, batch_id):
    """Recompute the Merkle root from the stored proofs and compare it."""
    user, err = _admin_guard(request)
    if err:
        return JsonResponse({'success': False, 'message': 'Not authorised.'}, status=403)

    try:
        batch = MithrilBatch.objects.get(batch_id=batch_id)
    except MithrilBatch.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Batch not found.'}, status=404)

    proofs = list(batch.proofs.order_by('created_at', 'pk'))
    leaves = [(p.signature or 'no_sig') for p in proofs]
    computed = compute_merkle_root(leaves)

    return JsonResponse({
        'success': True,
        'match': computed == (batch.merkle_root or ''),
        'stored_root': batch.merkle_root or '',
        'computed_root': computed,
        'declared_proofs': batch.num_proofs or 0,
        'actual_proofs': len(proofs),
        'count_match': len(proofs) == (batch.num_proofs or 0),
    })


# ==============================================================================
# 6. DELETE BATCH
# ==============================================================================

@require_POST
def delete_batch_view(request, batch_id):
    """Delete a batch and release its proofs back to the un-batched pool."""
    user, err = _admin_guard(request)
    if err:
        return JsonResponse({'success': False, 'message': 'Not authorised.'}, status=403)

    try:
        batch = MithrilBatch.objects.get(batch_id=batch_id)
    except MithrilBatch.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Batch not found.'}, status=404)

    released = batch.proofs.update(is_batched=False, batch=None)
    batch.delete()

    return JsonResponse({
        'success': True,
        'message': 'Batch %s deleted — %d proofs released back to pending.'
                    % (batch_id, released),
    })


# ==============================================================================
# urls.py
# ==============================================================================
#
# from django.urls import path
# from app import views
#
# urlpatterns = [
#     path('mithril-batches/',            views.mithril_batches_view, name='mithril_batches'),
#     path('process-batches/',            views.process_batches_view, name='process_batches'),
#     path('anchor-batch/<str:batch_id>/', views.anchor_batch_view,   name='anchor_batch'),
#     path('retry-batch/<str:batch_id>/',  views.retry_batch_view,    name='retry_batch'),
#     path('verify-batch/<str:batch_id>/', views.verify_batch_view,   name='verify_batch'),
#     path('delete-batch/<str:batch_id>/', views.delete_batch_view,   name='delete_batch'),
# ]





def export_batch_view(request, batch_id):
    #Export batch data as CSV
    try:
        batch = MithrilBatch.objects.get(id=batch_id)
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="batch_{batch.batch_id}_{datetime.now().strftime("%Y%m%d")}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Batch Export'])
        writer.writerow([f'Batch ID: {batch.batch_id}'])
        writer.writerow([f'Status: {batch.get_status_display()}'])
        writer.writerow([f'Proofs: {batch.num_proofs}'])
        writer.writerow([f'Merkle Root: {batch.merkle_root}'])
        writer.writerow([f'Aggregated Signature: {batch.aggregated_signature}'])
        writer.writerow([f'Created: {batch.created_at}'])
        writer.writerow([f'Anchored: {batch.anchored_at or "Not anchored"}'])
        writer.writerow([f'Tx Hash: {batch.tx_hash or "N/A"}'])
        writer.writerow([f'Block: {batch.block_number or "N/A"}'])
        writer.writerow([])
        writer.writerow(['Proof ID', 'Agent', 'Safety Score', 'Created'])
        
        for proof in batch.proofs.all():
            writer.writerow([
                proof.proof_id,
                proof.agent.name,
                proof.safety_score,
                proof.created_at
            ])
        
        return response
    except MithrilBatch.DoesNotExist:
        messages.error(request, 'Batch not found')
        return redirect('mithril_batches')
    except Exception as e:
        messages.error(request, f'Error exporting batch: {str(e)}')
        return redirect('mithril_batches')


def blockchain_tx_view(request):
    #Blockchain Transactions management page with dynamic data from database
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get filter parameters
    search = request.GET.get('search', '').strip()
    tx_type = request.GET.get('type', '')
    status_filter = request.GET.get('status', '')
    
    # Base queryset
    transactions = BlockchainTransaction.objects.all().prefetch_related('related_batch', 'related_agents')
    
    # Apply filters
    if search:
        transactions = transactions.filter(
            django_models.Q(tx_hash__icontains=search) |
            django_models.Q(tx_type__icontains=search) |
            django_models.Q(related_batch__batch_id__icontains=search) |
            django_models.Q(related_agents__agent_id__icontains=search)
        )
    
    if tx_type:
        transactions = transactions.filter(tx_type=tx_type)
    
    if status_filter:
        transactions = transactions.filter(status=status_filter)
    
    # Order by newest first
    transactions = transactions.order_by('-created_at')
    
    # ============ PAGINATION ============
    from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
    
    # Paginate - 10 records per page
    paginator = Paginator(transactions, 10)
    page_number = request.GET.get('page')
    
    try:
        page_obj = paginator.get_page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.get_page(1)
    except EmptyPage:
        page_obj = paginator.get_page(paginator.num_pages)
    
    # Calculate stats (using the full queryset, not paginated)
    total_tx = BlockchainTransaction.objects.count()
    successful_tx = BlockchainTransaction.objects.filter(status='success').count()
    failed_tx = BlockchainTransaction.objects.filter(status='failed').count()
    
    # Calculate average gas used
    gas_values = BlockchainTransaction.objects.filter(gas_used__isnull=False).values_list('gas_used', flat=True)
    avg_gas = round(sum(gas_values) / len(gas_values)) if gas_values else 0
    
    context = {
        'user': user,
        'transactions': page_obj,  # Use page_obj instead of transactions
        'page_obj': page_obj,
        'paginator': paginator,
        'total_tx': total_tx,
        'successful_tx': successful_tx,
        'failed_tx': failed_tx,
        'avg_gas': avg_gas,
        'search': search,
        'tx_type': tx_type,
        'status_filter': status_filter,
    }
    
    return render(request, 'admin/blockchain_tx.html', context)


def reports_view(request):
    #Reports & Analytics page with dynamic data from database
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # ============ STATS ============
    total_agents = Agent.objects.count()
    active_agents = Agent.objects.filter(status='active').count()
    total_users = Users.objects.count()
    active_users = Users.objects.filter(is_active=True).count()
    total_proofs = PoCAProof.objects.count()
    total_batches = MithrilBatch.objects.count()
    total_transactions = BlockchainTransaction.objects.count()
    
    # ============ PROOF STATS ============
    batched_proofs = PoCAProof.objects.filter(is_batched=True).count()
    pending_proofs = PoCAProof.objects.filter(is_batched=False).count()
    
    # ============ SAFETY SCORE ============
    avg_safety = PoCAProof.objects.aggregate(Avg('safety_score'))['safety_score__avg'] or 0
    avg_safety_percent = round(avg_safety * 100, 1)
    
    # ============ VERIFICATION RATE ============
    verification_rate = round((batched_proofs / total_proofs * 100) if total_proofs > 0 else 0, 1)
    
    # ============ BATCH STATS ============
    anchored_batches = MithrilBatch.objects.filter(status='anchored').count()
    pending_batches = MithrilBatch.objects.filter(status='pending').count()
    failed_batches = MithrilBatch.objects.filter(status='failed').count()
    
    # ============ TRANSACTION STATS ============
    successful_tx = BlockchainTransaction.objects.filter(status='success').count()
    failed_tx = BlockchainTransaction.objects.filter(status='failed').count()
    
    # ============ GAS STATS ============
    avg_gas = BlockchainTransaction.objects.filter(gas_used__isnull=False).aggregate(Avg('gas_used'))['gas_used__avg'] or 0
    avg_gas = int(avg_gas)
    
    # ============ AGENT PERFORMANCE (Top 5) ============
    agent_performance = Agent.objects.annotate(
        proof_count=Count('proofs')
    ).order_by('-proof_count')[:5]
    
    # ============ CHART DATA (Last 30 days) ============
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=30)
    
    # Get daily proof counts
    daily_proofs = []
    daily_transactions = []
    date_labels = []
    
    for i in range(30):
        date = start_date + timedelta(days=i)
        date_labels.append(date.strftime('%b %d'))
        
        # Proofs for this day
        proof_count = PoCAProof.objects.filter(
            created_at__date=date
        ).count()
        daily_proofs.append(proof_count)
        
        # Transactions for this day
        tx_count = BlockchainTransaction.objects.filter(
            created_at__date=date
        ).count()
        daily_transactions.append(tx_count)
    
    # ============ TRANSACTION DISTRIBUTION ============
    did_count = BlockchainTransaction.objects.filter(tx_type='did_registration').count()
    batch_count = BlockchainTransaction.objects.filter(tx_type='batch_anchor').count()
    
    context = {
        'user': user,
        # Stats
        'total_agents': total_agents,
        'active_agents': active_agents,
        'total_users': total_users,
        'active_users': active_users,
        'total_proofs': total_proofs,
        'total_batches': total_batches,
        'total_transactions': total_transactions,
        'batched_proofs': batched_proofs,
        'pending_proofs': pending_proofs,
        'avg_safety': avg_safety_percent,
        'verification_rate': verification_rate,
        'anchored_batches': anchored_batches,
        'pending_batches': pending_batches,
        'failed_batches': failed_batches,
        'successful_tx': successful_tx,
        'failed_tx': failed_tx,
        'avg_gas': avg_gas,
        # Chart Data
        'date_labels': date_labels,
        'daily_proofs': daily_proofs,
        'daily_transactions': daily_transactions,
        'did_count': did_count,
        'batch_count': batch_count,
        # Agent Performance
        'agent_performance': agent_performance,
        'now': datetime.now(),
    }
    
    return render(request, 'admin/reports.html', context)


def generate_report(request, report_type):
    #Generate and download report based on type
    # Check authentication
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access reports.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get format parameter (csv, json)
    format_type = request.GET.get('format', 'csv')
    
    # Generate report based on type
    if report_type == 'platform':
        return generate_platform_report(request, format_type, user)
    elif report_type == 'agents':
        return generate_agents_report(request, format_type, user)
    elif report_type == 'proofs':
        return generate_proofs_report(request, format_type, user)
    elif report_type == 'transactions':
        return generate_transactions_report(request, format_type, user)
    elif report_type == 'users':
        return generate_users_report(request, format_type, user)
    elif report_type == 'batches':
        return generate_batches_report(request, format_type, user)
    else:
        messages.error(request, 'Invalid report type')
        return redirect('reports')


def generate_platform_report(request, format_type, user):
    #Generate platform summary report
    data = {
        'report_title': 'Platform Summary Report',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'generated_by': user.username,
        'total_agents': Agent.objects.count(),
        'active_agents': Agent.objects.filter(status='active').count(),
        'total_users': Users.objects.count(),
        'active_users': Users.objects.filter(is_active=True).count(),
        'total_proofs': PoCAProof.objects.count(),
        'batched_proofs': PoCAProof.objects.filter(is_batched=True).count(),
        'pending_proofs': PoCAProof.objects.filter(is_batched=False).count(),
        'total_batches': MithrilBatch.objects.count(),
        'anchored_batches': MithrilBatch.objects.filter(status='anchored').count(),
        'total_transactions': BlockchainTransaction.objects.count(),
        'successful_tx': BlockchainTransaction.objects.filter(status='success').count(),
        'failed_tx': BlockchainTransaction.objects.filter(status='failed').count(),
    }
    
    return export_report(data, format_type, 'platform_report')


def generate_agents_report(request, format_type, user):
    #Generate agents performance report
    agents = Agent.objects.all().annotate(
        proof_count=Count('proofs')
    ).order_by('-proof_count')
    
    data = {
        'report_title': 'Agents Performance Report',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'generated_by': user.username,
        'agents': [
            {
                'name': agent.name,
                'agent_id': agent.agent_id,
                'provider': agent.get_llm_provider_display(),
                'model': agent.model_name,
                'status': agent.get_status_display(),
                'proof_count': agent.proof_count,
                'created_at': agent.created_at.strftime('%Y-%m-%d %H:%M'),
            }
            for agent in agents
        ]
    }
    
    return export_report(data, format_type, 'agents_report')


def generate_proofs_report(request, format_type, user):
    #Generate proofs report
    proofs = PoCAProof.objects.all().select_related('agent', 'submitted_by').order_by('-created_at')[:100]
    
    data = {
        'report_title': 'PoCA Proofs Report',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'generated_by': user.username,
        'total_proofs': PoCAProof.objects.count(),
        'proofs': [
            {
                'proof_id': proof.proof_id,
                'agent': proof.agent.name,
                'submitted_by': proof.submitted_by.username,
                'safety_score': proof.safety_score,
                'is_batched': 'Yes' if proof.is_batched else 'No',
                'created_at': proof.created_at.strftime('%Y-%m-%d %H:%M'),
            }
            for proof in proofs
        ]
    }
    
    return export_report(data, format_type, 'proofs_report')


def generate_transactions_report(request, format_type, user):
    #Generate blockchain transactions report
    transactions = BlockchainTransaction.objects.all().select_related('related_batch', 'related_agent').order_by('-created_at')[:100]
    
    data = {
        'report_title': 'Blockchain Transactions Report',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'generated_by': user.username,
        'total_transactions': BlockchainTransaction.objects.count(),
        'transactions': [
            {
                'tx_hash': tx.tx_hash[:20] + '...',
                'type': tx.get_tx_type_display(),
                'status': tx.get_status_display(),
                'block': tx.block_number or 'N/A',
                'gas_used': tx.gas_used or 'N/A',
                'created_at': tx.created_at.strftime('%Y-%m-%d %H:%M'),
            }
            for tx in transactions
        ]
    }
    
    return export_report(data, format_type, 'transactions_report')


def generate_users_report(request, format_type, user):
    #Generate users report
    users = Users.objects.all().order_by('-created_at')
    
    data = {
        'report_title': 'Users Report',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'generated_by': user.username,
        'total_users': Users.objects.count(),
        'users': [
            {
                'username': u.username,
                'email': u.email,
                'role': u.get_role_display(),
                'status': 'Active' if u.is_active else 'Inactive',
                'joined': u.created_at.strftime('%Y-%m-%d %H:%M'),
            }
            for u in users
        ]
    }
    
    return export_report(data, format_type, 'users_report')


def generate_batches_report(request, format_type, user):
    #Generate batches report
    batches = MithrilBatch.objects.all().order_by('-created_at')
    
    data = {
        'report_title': 'Mithril Batches Report',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'generated_by': user.username,
        'total_batches': MithrilBatch.objects.count(),
        'batches': [
            {
                'batch_id': batch.batch_id,
                'merkle_root': batch.merkle_root[:20] + '...',
                'num_proofs': batch.num_proofs,
                'status': batch.get_status_display(),
                'tx_hash': batch.tx_hash[:20] + '...' if batch.tx_hash else 'Not anchored',
                'block_number': batch.block_number or 'N/A',
                'created_at': batch.created_at.strftime('%Y-%m-%d %H:%M'),
            }
            for batch in batches
        ]
    }
    
    return export_report(data, format_type, 'batches_report')


def export_report(data, format_type, filename_prefix):
    #Export data in requested format
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}"
    
    if format_type == 'csv':
        return export_csv(data, filename)
    elif format_type == 'json':
        return export_json(data, filename)
    else:
        # Default to CSV
        return export_csv(data, filename)


def export_csv(data, filename):
    #Export data as CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([data.get('report_title', 'Report')])
    writer.writerow([f"Generated: {data.get('generated_at', '')}"])
    writer.writerow([f"Generated By: {data.get('generated_by', '')}"])
    writer.writerow([])
    
    # Find the data list
    for key, value in data.items():
        if isinstance(value, list) and value:
            # Get headers from first item
            headers = list(value[0].keys())
            writer.writerow(headers)
            
            # Write data rows
            for item in value:
                writer.writerow([item.get(h, '') for h in headers])
            break
    
    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}.csv"'
    return response


def export_json(data, filename):
    #Export data as JSON
    response = HttpResponse(json.dumps(data, indent=2), content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="{filename}.json"'
    return response


def attack_logs_page_view(request):
    # Display all attack logs in a dedicated page
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access this page.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    if user.role != 'admin':
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('index')
    
    # Get filters
    search = request.GET.get('search', '').strip()
    attack_type_filter = request.GET.get('attack_type', '')
    severity_filter = request.GET.get('severity', '')
    
    logs = AttackLog.objects.all().order_by('-detected_at')
    
    if search:
        logs = logs.filter(
            models.Q(description__icontains=search) |
            models.Q(attack_type__icontains=search) |
            models.Q(agent_id__icontains=search) |
            models.Q(proof_id__icontains=search)
        )
    
    if attack_type_filter:
        logs = logs.filter(attack_type=attack_type_filter)
    
    if severity_filter:
        logs = logs.filter(severity=severity_filter)
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'user': user,
        'logs': page_obj,
        'page_obj': page_obj,
        'paginator': paginator,
        'total_attacks': AttackLog.objects.count(),
        'critical_count': AttackLog.objects.filter(severity='critical').count(),
        'high_count': AttackLog.objects.filter(severity='high').count(),
        'medium_count': AttackLog.objects.filter(severity='medium').count(),
        'low_count': AttackLog.objects.filter(severity='low').count(),
        'search': search,
        'attack_type_filter': attack_type_filter,
        'severity_filter': severity_filter,
    }
    
    return render(request, 'admin/attack_logs.html', context)


# User actions views
def user_dashboard_view(request):
    #User dashboard with dynamic statistics from database
    # Check if user is authenticated
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to access your dashboard.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    # ============ STATS ============
    total_queries = PoCAProof.objects.filter(submitted_by=user).count()
    verified_queries = PoCAProof.objects.filter(
        submitted_by=user, 
        is_batched=True, 
        safety_score__gte=0.7
    ).count()
    pending_queries = PoCAProof.objects.filter(
        submitted_by=user, 
        is_batched=False
    ).count()
    
    # Calculate verification rate
    verification_rate = round((verified_queries / total_queries * 100) if total_queries > 0 else 0, 1)
    
    # ============ AVAILABLE AGENTS ============
    available_agents = Agent.objects.filter(status='active').order_by('name')
    available_agents_count = available_agents.count()
    
    # ============ RECENT QUERIES (Last 5) ============
    recent_queries = PoCAProof.objects.filter(
        submitted_by=user
    ).select_related('agent', 'batch').order_by('-created_at')[:5]
    
    # Prepare recent queries data
    recent_queries_data = []
    for query in recent_queries:
        # Determine status
        if query.is_batched and query.safety_score >= 0.7:
            status = 'verified'
            status_display = 'Verified'
        elif query.is_batched:
            status = 'verified'
            status_display = 'Verified'
        elif query.safety_score == 0.0:
            status = 'processing'
            status_display = 'Processing'
        elif query.safety_score < 0.5:
            status = 'failed'
            status_display = 'Failed'
        else:
            status = 'pending'
            status_display = 'Pending'
        
        # Get agent emoji
        agent_name = query.agent.name.lower()
        if 'medical' in agent_name or 'health' in agent_name:
            emoji = '🏥'
        elif 'code' in agent_name or 'review' in agent_name:
            emoji = '💻'
        elif 'data' in agent_name or 'analytics' in agent_name:
            emoji = '📊'
        elif 'legal' in agent_name or 'law' in agent_name:
            emoji = '⚖️'
        elif 'finance' in agent_name or 'investment' in agent_name:
            emoji = '💰'
        else:
            emoji = '🤖'
        
        # Get blockchain details if proof is batched
        tx_hash = 'Pending'
        merkle_root = None
        batch_id = None
        aggregated_signature = None
        block_number = None
        gas_used = None
        anchored_at = None
        
        if query.batch:
            batch_id = query.batch.batch_id
            merkle_root = query.batch.merkle_root
            aggregated_signature = query.batch.aggregated_signature
            tx_hash = query.batch.tx_hash if query.batch.tx_hash else 'Pending'
            block_number = query.batch.block_number if query.batch.block_number else None
            gas_used = query.batch.gas_used if hasattr(query.batch, 'gas_used') else None
            anchored_at = query.batch.anchored_at if query.batch.anchored_at else None
            
            # If batch is anchored but tx_hash is None, try to get from blockchain transaction
            if query.batch.status == 'anchored' and (not tx_hash or tx_hash == 'Pending'):
                from app.models import BlockchainTransaction
                blockchain_tx = BlockchainTransaction.objects.filter(related_batch=query.batch).order_by('-created_at').first()
                if blockchain_tx:
                    tx_hash = blockchain_tx.tx_hash
                    block_number = blockchain_tx.block_number if blockchain_tx.block_number else block_number
                    gas_used = blockchain_tx.gas_used if blockchain_tx.gas_used else gas_used
        
        recent_queries_data.append({
            'query': query,
            'status': status,
            'status_display': status_display,
            'emoji': emoji,
            'safety_percent': round(query.safety_score * 100, 1),
            'agent_did': query.agent.did if query.agent.did else 'N/A',
            'agent_name': query.agent.name,
            'tx_hash': tx_hash,
            'merkle_root': merkle_root,
            'batch_id': batch_id,
            'aggregated_signature': aggregated_signature,
            'block_number': block_number,
            'gas_used': gas_used,
            'anchored_at': anchored_at,
        })
    
    context = {
        'user': user,
        'total_queries': total_queries,
        'verified_queries': verified_queries,
        'pending_queries': pending_queries,
        'verification_rate': verification_rate,
        'available_agents': available_agents_count,
        'recent_queries': recent_queries_data,  
    }
    
    return render(request, 'user/dashboard.html', context)


def download_response_view(request, proof_id):
    #Download a single response as text file
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to download.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id, submitted_by=user)
        
        response = HttpResponse(content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="response_{proof.proof_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"'
        
        content = f"""
            ===============================================================================
            SECUREAI PLATFORM - RESPONSE DOWNLOAD
            ===============================================================================
            
            PROOF ID: {proof.proof_id}
            AGENT: {proof.agent.name}
            SUBMITTED BY: {proof.submitted_by.username}
            CREATED: {proof.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            SAFETY SCORE: {proof.safety_score * 100:.1f}%
            STATUS: {'Verified' if proof.is_batched else 'Pending'}
            
            ===============================================================================
            QUERY
            ===============================================================================
            {proof.query_text}
            
            ===============================================================================
            RESPONSE
            ===============================================================================
            {proof.ai_response}
            
            ===============================================================================
            CRYPTOGRAPHIC PROOF
            ===============================================================================
            Context Hash: {proof.context_hash}
            Model Hash: {proof.model_hash}
            Signature: {proof.signature[:100]}...
            ===============================================================================
        """
        
        response.write(content)
        return response
        
    except PoCAProof.DoesNotExist:
        messages.error(request, 'Proof not found')
        return redirect('my_history')
    except Exception as e:
        messages.error(request, f'Error downloading: {str(e)}')
        return redirect('my_history')


"""
Corrected submit-query related functions for SecureAI views.py.

Important behavior:
1. AI provider errors are raised, not returned as normal AI text.
2. Empty/invalid AI responses STOP the workflow.
3. Safety score is calculated ONLY after a valid AI response exists.
4. Safety-score errors STOP proof creation; no default/fake score is used.
5. Groq and Hugging Face calls are delegated to the corrected crypto_utils.py,
   so there is only one implementation of each provider integration.
6. PoCA proof, blockchain registration, and Mithril batching happen only
   after successful AI generation and safety scoring.
"""
import re
import traceback

from django.contrib import messages
from django.shortcuts import redirect, render

from .models import Users, Agent, PoCAProof
from .blockchain.logic import addNewData
from .crypto_utils import (
    decrypt_value,
    generate_context_hash,
    generate_groq_response,
    generate_huggingface_response,
    generate_model_hash,
    generate_ollama_response,
    generate_proof_id,
    generate_signature,
)

# AI RESPONSE HELPERS
AI_ERROR_PREFIXES = (
    "error generating response",
    "openai error",
    "groq error",
    "groq api error",
    "hugging face error",
    "hugging face api error",
    "ollama error",
    "unknown provider",
)


def _validate_ai_response(ai_response):
    """
    Ensure that provider output is a real, non-empty AI response.
    This is defense-in-depth. The corrected provider functions in
    crypto_utils.py already raise exceptions on API failures, but this
    prevents an old/error-string implementation from accidentally being
    scored and written to the blockchain.
    """
    if ai_response is None:
        raise RuntimeError("AI provider returned no response.")
    
    if not isinstance(ai_response, str):
        raise RuntimeError(
            f"AI provider returned an invalid response type: "
            f"{type(ai_response).__name__}"
        )
        
    cleaned = ai_response.strip()
    
    if not cleaned:
        raise RuntimeError("AI provider returned an empty response.")
    
    lowered = cleaned.lower()
    
    if any(lowered.startswith(prefix) for prefix in AI_ERROR_PREFIXES):
        raise RuntimeError(cleaned)
    
    return cleaned


# CLEAN AI RESPONSE FORMATTER
def clean_ai_response(raw_response):
    """
    Clean AI response by removing markdown symbols, special characters,
    and formatting it into clean, readable plain text.
    Removes: *, _, +, #, ~, `, >, -, =, [], (), etc.
    Preserves: spaces, newlines, periods, commas, question marks.
    """
    if not raw_response:
        return ""
    
    # Step 1: Remove markdown headers (###, ##, #)
    cleaned = re.sub(r'^#{1,6}\s*', '', raw_response, flags=re.MULTILINE)
    
    # Step 2: Remove bold/italic markers (*, _, ~)
    cleaned = re.sub(r'\*\*([^*]+)\*\*', r'\1', cleaned)  # **bold**
    cleaned = re.sub(r'\*([^*]+)\*', r'\1', cleaned)      # *italic*
    cleaned = re.sub(r'__([^_]+)__', r'\1', cleaned)      # __bold__
    cleaned = re.sub(r'_([^_]+)_', r'\1', cleaned)        # _italic_
    cleaned = re.sub(r'~~([^~]+)~~', r'\1', cleaned)      # ~~strikethrough~~
    
    # Step 3: Remove inline code and code blocks
    cleaned = re.sub(r'`([^`]+)`', r'\1', cleaned)        # `code`
    cleaned = re.sub(r'```[^`]*```', '', cleaned)         # ```code blocks```
    
    # Step 4: Remove blockquotes (>, >>)
    cleaned = re.sub(r'^>\s*', '', cleaned, flags=re.MULTILINE)
    
    # Step 5: Remove list markers (*, -, +, numbers)
    cleaned = re.sub(r'^[\*\-\+]\s+', '• ', cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r'^\d+\.\s+', '• ', cleaned, flags=re.MULTILINE)
    
    # Step 6: Remove horizontal rules (---, ===, ***)
    cleaned = re.sub(r'^[-=*]{3,}\s*$', '', cleaned, flags=re.MULTILINE)
    
    # Step 7: Remove extra special characters but keep punctuation
    cleaned = re.sub(r'[\[\]\(\)\{\}]', '', cleaned)      # Remove brackets
    cleaned = re.sub(r'[\\/|]', '', cleaned)              # Remove slashes and pipe
    cleaned = re.sub(r'&[a-zA-Z]+;', '', cleaned)         # Remove HTML entities
    
    # Step 8: Fix spacing - remove extra spaces and lines
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)          # Max 2 newlines
    cleaned = re.sub(r' {2,}', ' ', cleaned)              # Single spaces only
    
    # Step 9: Trim whitespace
    cleaned = cleaned.strip()
    
    # Step 10: Capitalize first letter of each sentence
    sentences = re.split(r'(?<=[.!?])\s+', cleaned)
    formatted_sentences = []
    for sentence in sentences:
        if sentence:
            formatted_sentences.append(sentence[0].upper() + sentence[1:])
    cleaned = ' '.join(formatted_sentences)
    
    return cleaned


def format_ai_response_for_display(raw_response):
    """
    Format AI response for clean display with proper paragraphs.
    This is the main function you call before displaying the response.
    """
    if not raw_response:
        return "No response available."
    
    # Clean the response
    cleaned = clean_ai_response(raw_response)
    
    # If cleaning removed everything, return a fallback
    if not cleaned or len(cleaned.strip()) < 10:
        return "Response received but could not be formatted properly."
    
    return cleaned


def generate_ai_response(agent, query_text):
    """
    Generate an AI response using the provider configured for the agent.
    Returns a clean, formatted response without markdown or special symbols.
    """
    if agent is None:
        raise ValueError("Agent is required.")
    
    if not query_text or not query_text.strip():
        raise ValueError("Query text is required.")
    
    provider = (agent.llm_provider or "").strip().lower()
    model_name = (agent.model_name or "").strip()
    
    if not provider:
        raise ValueError("Agent LLM provider is not configured.")
    
    if not model_name:
        raise ValueError("Agent model name is not configured.")
    
    print(f"🔍 Debug: Provider = {provider}, Model = {model_name}")
    
    system_prompt = (
        f"You are {agent.name}. "
        f"{agent.description or 'A helpful AI assistant.'} "
        "Provide clear, accurate, helpful, and concise responses. "
        "DO NOT use markdown, asterisks, underscores, or any special "
        "formatting symbols. Use plain text with proper punctuation "
        "and spacing only."
    )
    
    if provider == "openai":
        if not agent.api_key_encrypted:
            raise RuntimeError("OpenAI API key is not configured for this agent.")
        api_key = decrypt_value(agent.api_key_encrypted)
        ai_response = generate_openai_response(
            api_key=api_key,
            model_name=model_name,
            query_text=query_text,
            system_prompt=system_prompt,
        )
        
    elif provider == "groq":
        if not agent.api_key_encrypted:
            raise RuntimeError("Groq API key is not configured for this agent.")
        api_key = decrypt_value(agent.api_key_encrypted)
        ai_response = generate_groq_response(
            api_key=api_key,
            model_name=model_name,
            query_text=query_text,
            system_prompt=system_prompt,
        )
        
    elif provider == "huggingface":
        if not agent.api_key_encrypted:
            raise RuntimeError("Hugging Face API token is not configured for this agent.")
        api_key = decrypt_value(agent.api_key_encrypted)
        ai_response = generate_huggingface_response(
            api_key=api_key,
            model_name=model_name,
            query_text=query_text,
            system_prompt=system_prompt,
        )
        
    elif provider == "ollama":
        print(f"🔍 Calling Ollama with model: {model_name}")
        ai_response = generate_ollama_response(
            model_name=model_name,
            query_text=query_text,
            system_prompt=system_prompt,
        )
        
    else:
        raise ValueError(f"Unsupported AI provider: {provider}")
    
    # VALIDATE the raw response first
    validated_response = _validate_ai_response(ai_response)
    
    # THEN clean it for display
    clean_response = format_ai_response_for_display(validated_response)
    
    return clean_response


def generate_openai_response(
    api_key,
    model_name,
    query_text,
    system_prompt=None,
):
    """
    Generate response using the OpenAI Python SDK.
    This function also raises provider errors instead of returning them as
    normal response text.
    """
    if not api_key:
        raise ValueError("OpenAI API key is required.")
    
    if not model_name:
        raise ValueError("OpenAI model name is required.")
    
    if not query_text or not query_text.strip():
        raise ValueError("Query text is required.")
    
    try:
        import openai
    except ImportError as exc:
        raise RuntimeError(
            "OpenAI package is not installed. Run: pip install openai"
        ) from exc
        
    try:
        client = openai.OpenAI(api_key=api_key)
        
        messages_payload = []
        
        if system_prompt:
            messages_payload.append(
                {"role": "system", "content": system_prompt}
            )
            
        messages_payload.append(
            {"role": "user", "content": query_text}
        )
        
        response = client.chat.completions.create(
            model=model_name,
            messages=messages_payload,
            temperature=0.7,
            max_tokens=2000,
        )
        
        content = response.choices[0].message.content
        
    except Exception as exc:
        raise RuntimeError(f"OpenAI API request failed: {exc}") from exc
    
    return _validate_ai_response(content)


# SAFETY SCORE
def calculate_safety_score(ai_response):
    """
    Calculate the existing heuristic safety score.
    IMPORTANT:
    - This function must only receive a valid AI response.
    - It does NOT return a fake/default score when scoring fails.
    - Any scoring failure raises an exception and stops proof generation.
    This keeps your existing 0.0-1.0 scoring idea while avoiding substring
    mistakes such as counting "harm" inside "harmless".
    """
    response = _validate_ai_response(ai_response)
    response_lower = response.lower()
    
    unsafe_keywords = [
        "harm",
        "violence",
        "attack",
        "dangerous",
        "illegal",
        "discrimination",
        "hate",
        "abuse",
        "exploit",
        "threat",
    ]
    safe_indicators = [
        "consult",
        "doctor",
        "professional",
        "please",
        "recommend",
        "safety",
        "careful",
        "caution",
        "help",
        "support",
    ]
    
    def count_whole_words(words):
        total = 0
        
        for word in words:
            pattern = rf"\b{re.escape(word)}\b"
            if re.search(pattern, response_lower):
                total += 1
        return total
    unsafe_count = count_whole_words(unsafe_keywords)
    safe_count = count_whole_words(safe_indicators)
    unsafe_score = min(unsafe_count / 5, 1.0)
    safe_score = min(safe_count / 5, 1.0)
    final_score = (
        max(0.5, 1.0 - (unsafe_score * 0.5))
        * (0.8 + (safe_score * 0.2))
    )
    safety_score = max(0.0, min(1.0, final_score))
    return round(safety_score, 2)


from .proof_acceptance import accept_poca_proof
import uuid
from django.db import IntegrityError, transaction, OperationalError
from .models import ProcessedRequest
from django.utils import timezone

# SUBMIT QUERY
def submit_query_view(request):
    """
    Submit a query to an AI agent and create a verified PoCA proof.
    Critical rule:
        NO successful AI response
        -> NO safety score
        -> NO cryptographic proof
        -> NO database proof
        -> NO Mithril processing
    IMPORTANT (fixed):
    Individual proofs are NEVER written to the blockchain here.
    Only MithrilBatchProcessor.anchor_batch() writes to the blockchain,
    once per batch of BATCH_SIZE proofs. This is what makes the
    Mithril batching cost-reduction claim real instead of fabricated —
    previously this view called addNewData() per proof AND the batch
    processor called it again per batch, paying for both.
    """
    
    print("=" * 60)
    print("SUBMIT QUERY VIEW - START")
    print("=" * 60)
    # Authentication
    if not request.session.get("is_authenticated", False):
        messages.error(request, "Please login to submit a query.")
        return redirect("index")
    
    user_id = request.session.get("user_id")
    if not user_id:
        request.session.flush()
        messages.error(request, "Session expired. Please login again.")
        return redirect("index")
    try:
        user = Users.objects.get(id=user_id)
        print(f"User found: {user.username} (ID: {user.id})")
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, "Session expired. Please login again.")
        return redirect("index")
    # Active agents / GET selection
    agents = Agent.objects.filter(status="active").order_by("name")
    print(f"Found {agents.count()} active agents")
    selected_agent_id = request.GET.get("agent")
    selected_agent = None
    if selected_agent_id:
        try:
            selected_agent = Agent.objects.get(
                id=selected_agent_id,
                status="active",
            )
            print(
                f"Selected agent from URL: "
                f"{selected_agent.name} (ID: {selected_agent.id})"
            )
        except Agent.DoesNotExist:
            print(f"Agent with ID {selected_agent_id} not found")
            selected_agent = None
    # POST submission
    if request.method == "POST":
        print("\nPOST Request Received")
        agent_id = request.POST.get("agent_id")
        query_text = request.POST.get("query_text", "").strip()
        print(f"   Agent ID: {agent_id}")
        print(f"   Query Text: {query_text[:50]}...")
        # Input validation
        if not agent_id:
            print("Validation failed: No agent selected")
            messages.error(request, "Please select an AI agent.")
            return redirect("submit_query")
        
        request_id = request.POST.get("request_id", "").strip()
        if not request_id or len(request_id) > 128:
            messages.error(
                request,
                "Invalid or missing request ID. Please reload the form."
            )
            return redirect("submit_query")
        
        if not query_text:
            print("Validation failed: No query text")
            messages.error(request, "Please enter your query.")
            return redirect("submit_query")
        if len(query_text) < 10:
            print(
                f"Validation failed: Query too short "
                f"({len(query_text)} chars)"
            )
            messages.error(
                request,
                "Please provide more details (minimum 10 characters).",
            )
            return redirect("submit_query")
        # Agent validation
        try:
            agent = Agent.objects.get(
                id=agent_id,
                status="active",
            )
        except Agent.DoesNotExist:
            print(f"Agent with ID {agent_id} not found")
            messages.error(request, "Selected agent not found.")
            return redirect("submit_query")
        provider = (agent.llm_provider or "").strip().lower()
        model_name = (agent.model_name or "").strip()
        print(f"Agent found: {agent.name} (ID: {agent.id})")
        print(f"   Provider: {provider}")
        print(f"   Model: {model_name}")
        print(
            f"   Has private key: "
            f"{bool(agent.private_key_encrypted)}"
        )
        print(
            f"   Has API key: "
            f"{bool(agent.api_key_encrypted)}"
        )
        # Reject invalid agent configuration BEFORE spending
        # an external API request.
        if not provider:
            messages.error(
                request,
                "The selected agent has no AI provider configured.",
            )
            return redirect("submit_query")
        if not model_name:
            messages.error(
                request,
                "The selected agent has no model configured.",
            )
            return redirect("submit_query")
        if provider not in {
            "openai",
            "groq",
            "huggingface",
            "ollama",
        }:
            messages.error(
                request,
                f"Unsupported AI provider: {provider}",
            )
            return redirect("submit_query")
        if provider != "ollama" and not agent.api_key_encrypted:
            messages.error(
                request,
                f"{provider.title()} API key/token "
                f"is not configured for this agent.",
            )
            return redirect("submit_query")
        # A proof cannot be produced without the private key.
        if not agent.private_key_encrypted:
            messages.error(
                request,
                "This agent has no private signing key. "
                "The query was not sent to the AI provider.",
            )
            return redirect("submit_query")
        
        # Claim the request ID atomically before processing.
        try:
            with transaction.atomic():
                ProcessedRequest.objects.create(
                    request_id=request_id
                )
        except IntegrityError:
            messages.error(
                request,
                "This request has already been processed or submitted."
            )
            return redirect("submit_query")
        except OperationalError:
            messages.error(
                request,
                "The request could not be claimed because the database is busy. "
                "Please try again."
            )
            return redirect("submit_query")
        
        # STEP 1: AI RESPONSE
        try:
            print("\nSTEP 1: Generating AI Response...")
            ai_response = generate_ai_response(
                agent=agent,
                query_text=query_text,
            )
            # Defense-in-depth validation.
            ai_response = _validate_ai_response(ai_response)
            print(
                f"AI Response generated "
                f"({len(ai_response)} chars)"
            )
            print(f"   Preview: {ai_response[:100]}...")
        except Exception as exc:
            print("\nAI RESPONSE GENERATION FAILED")
            print(f"   Provider: {provider}")
            print(f"   Model: {model_name}")
            print(f"   Error: {exc}")
            traceback.print_exc()
            # IMPORTANT:
            # Return immediately.
            # Safety scoring/proof code will NOT run.
            messages.error(
                request,
                f"AI response could not be generated: {exc}",
            )
            return redirect("submit_query")
        # STEP 2: SAFETY SCORE
        try:
            print("\nSTEP 2: Calculating Safety Score...")
            safety_score = calculate_safety_score(ai_response)
            print(f"Safety Score: {safety_score}")
        except Exception as exc:
            print("\nSAFETY SCORE CALCULATION FAILED")
            print(f"   Error: {exc}")
            traceback.print_exc()
            # IMPORTANT:
            # No score = no proof.
            messages.error(
                request,
                f"Safety score could not be calculated: {exc}",
            )
            return redirect("submit_query")
        
        # STEP 3: CRYPTOGRAPHIC PROOF DATA
        try:
            print("\nSTEP 3: Generating Cryptographic Proof...")
            
            # 1. Generate proof ID
            proof_id = generate_proof_id()
            
            # 2. Generate context hash
            context_hash = generate_context_hash(
                query_text,
                user.id,
                agent.id,
            )
            
            if not context_hash:
                raise RuntimeError("Context hash generation returned an empty value.")
            
            # 3. Generate model hash BEFORE signing
            # current_model_hash = generate_model_hash(
            #     provider,
            #     model_name,
            # )
            
            current_model_hash = agent.model_hash

            if not current_model_hash:
                raise RuntimeError(
                    "Agent has no registered model hash."
                )
            
            # 4. Generate timestamp BEFORE signing
            attestation_timestamp = timezone.now()
            
            # 5. Sign the canonical PoCA fields
            signature = generate_signature(
                proof_id=proof_id,
                agent_did=agent.did,
                context_hash=context_hash,
                model_hash=current_model_hash,
                timestamp=attestation_timestamp.isoformat(),
                safety_score=safety_score,
                private_key_encrypted=agent.private_key_encrypted,
            )
            
            if not signature:
                raise RuntimeError("Signature generation returned an empty value.")
            
            print(f"Proof ID: {proof_id}")
            print(f"Context Hash: {context_hash}")
            print(f"Model Hash: {current_model_hash}")
            print(f"Signature: {signature[:30]}...")
            
        except Exception as exc:
            print(f"Cryptographic proof generation failed: {exc}")
            traceback.print_exc()
            
            messages.error(
                request,
                f"Cryptographic proof could not be generated: {exc}",
            )
            return redirect("submit_query")
        
        # STEP 4: SAVE VALID PROOF TO DATABASE
        try:
            print("\nSTEP 4: Saving to Database...")
            proof = PoCAProof(
                proof_id=proof_id,
                agent=agent,
                submitted_by=user,
                query_text=query_text,
                ai_response=ai_response,
                context_hash=context_hash,
                model_hash=current_model_hash,
                safety_score=safety_score,
                attestation_timestamp=attestation_timestamp,
                signature=signature,
                is_batched=False,
            )
            proof.save()
            
            accepted, acceptance_status = accept_poca_proof(proof.proof_id)
            
            if not accepted:
                messages.error(
                    request,
                    f"Proof was saved but not accepted: {acceptance_status}. "
                    "It has not entered the anchoring queue.",
                )
                return redirect("submit_query")
            
            print(f"Proof accepted: {proof_id}")
            print(f"Proof saved: {proof_id}")
        except Exception as exc:
            print("\n DATABASE SAVE FAILED")
            print(f"   Error: {exc}")
            traceback.print_exc()
            messages.error(
                request,
                f"Proof could not be saved: {exc}",
            )
            return redirect("submit_query")
        # Proof is saved and pending batch. NO individual blockchain
        # write happens here — only MithrilBatchProcessor writes to
        # the chain, once per batch, in STEP 5 below.
        messages.success(
            request,
            f"Query submitted successfully! Proof ID: {proof_id}. "
            "It will be anchored on-chain once batched with other proofs."
        )
        # STEP 5: MITHRIL BATCH PROCESSING
        try:
            print(
                "\nSTEP 5: Processing Mithril Batches..."
            )
            from .batch_processor import MithrilBatchProcessor
            print("   Checking pending proofs...")
            pending_count = (
                MithrilBatchProcessor.get_pending_count()
            )
            print(f"   Pending proofs: {pending_count}")
            if (
                pending_count
                >= MithrilBatchProcessor.BATCH_SIZE
            ):
                batch, batch_message = (
                    MithrilBatchProcessor.create_batch()
                )
                print(
                    f"   Batch processing result: "
                    f"{batch_message}"
                )
                if batch:
                    print(
                        f"Batch created: "
                        f"{batch.batch_id}"
                    )
                    messages.info(
                        request,
                        f"📦 {batch_message}",
                    )
            else:
                print(
                    "ℹ️ Not enough proofs "
                    f"({pending_count}/"
                    f"{MithrilBatchProcessor.BATCH_SIZE})"
                )
                messages.info(
                    request,
                    f"📦 {pending_count} proofs pending batch. "
                    "Batch will be created when threshold "
                    f"({MithrilBatchProcessor.BATCH_SIZE}) "
                    "is met.",
                )
        except Exception as exc:
            print(
                f"Batch processing error: {exc}"
            )
            traceback.print_exc()
            messages.warning(
                request,
                f"Proof was created, but Mithril batch "
                f"processing failed: {exc}",
            )
        print("\n" + "=" * 60)
        print("SUBMIT QUERY - COMPLETED")
        print("=" * 60)
        return redirect("my_history")
    # GET rendering
    context = {
        "user": user,
        "agents": agents,
        "selected_agent": selected_agent,
        "request_id": str(uuid.uuid4()),
    }

    return render(request, "user/submit_query.html", context)




from django.core.paginator import Paginator
def my_history_view(request):
    #Display user's query history with filters
    # Check if user is authenticated
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to view your history.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    # Get filter parameters
    search = request.GET.get('search', '').strip()
    agent_filter = request.GET.get('agent', '')
    status_filter = request.GET.get('status', '')
    date_filter = request.GET.get('date', '')
    
    # Base queryset - only user's own queries with related data
    proofs = PoCAProof.objects.filter(submitted_by=user).select_related('agent', 'batch')
    
    # Apply filters
    if search:
        proofs = proofs.filter(
            django_models.Q(proof_id__icontains=search) |
            django_models.Q(query_text__icontains=search) |
            django_models.Q(agent__name__icontains=search)
        )
    
    if agent_filter:
        proofs = proofs.filter(agent__id=agent_filter)
    
    if status_filter:
        if status_filter == 'verified':
            proofs = proofs.filter(is_batched=True, safety_score__gte=0.7)
        elif status_filter == 'pending':
            proofs = proofs.filter(is_batched=False)
        elif status_filter == 'processing':
            proofs = proofs.filter(is_batched=False, safety_score=0.0)
        elif status_filter == 'failed':
            proofs = proofs.filter(is_batched=False, safety_score__lt=0.5)
    
    if date_filter:
        from datetime import datetime, timedelta
        today = datetime.now().date()
        if date_filter == 'today':
            proofs = proofs.filter(created_at__date=today)
        elif date_filter == 'week':
            week_ago = today - timedelta(days=7)
            proofs = proofs.filter(created_at__date__gte=week_ago)
        elif date_filter == 'month':
            month_ago = today - timedelta(days=30)
            proofs = proofs.filter(created_at__date__gte=month_ago)
        elif date_filter == 'year':
            year_ago = today - timedelta(days=365)
            proofs = proofs.filter(created_at__date__gte=year_ago)
    
    # Order by newest first
    proofs = proofs.order_by('-created_at')
    
    # ============ PAGINATION ============
    from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
    
    # Paginate - 10 records per page
    paginator = Paginator(proofs, 10)
    page_number = request.GET.get('page')
    
    try:
        page_obj = paginator.get_page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.get_page(1)
    except EmptyPage:
        page_obj = paginator.get_page(paginator.num_pages)
    
    # Calculate stats (using the full queryset, not paginated)
    total_queries = PoCAProof.objects.filter(submitted_by=user).count()
    verified_queries = PoCAProof.objects.filter(submitted_by=user, is_batched=True, safety_score__gte=0.7).count()
    pending_queries = PoCAProof.objects.filter(submitted_by=user, is_batched=False).count()
    
    # Calculate verification rate
    verification_rate = round((verified_queries / total_queries * 100) if total_queries > 0 else 0, 1)
    
    # Get all agents for filter dropdown (only those user has used)
    user_agents = Agent.objects.filter(proofs__submitted_by=user).distinct().order_by('name')
    
    # Prepare proof data for the current page
    proof_data = []
    for proof in page_obj:
        # Determine status
        if proof.is_batched and proof.safety_score >= 0.7:
            status = 'verified'
            status_display = 'Verified'
        elif proof.is_batched:
            status = 'verified'
            status_display = 'Verified'
        elif proof.safety_score == 0.0:
            status = 'processing'
            status_display = 'Processing'
        elif proof.safety_score < 0.5:
            status = 'failed'
            status_display = 'Failed'
        else:
            status = 'pending'
            status_display = 'Pending'
        
        # Get agent emoji based on name/description
        agent_name = proof.agent.name.lower()
        if 'medical' in agent_name or 'health' in agent_name:
            emoji = '🏥'
        elif 'code' in agent_name or 'review' in agent_name:
            emoji = '💻'
        elif 'data' in agent_name or 'analytics' in agent_name:
            emoji = '📊'
        elif 'legal' in agent_name or 'law' in agent_name:
            emoji = '⚖️'
        elif 'finance' in agent_name or 'investment' in agent_name:
            emoji = '💰'
        else:
            emoji = '🤖'
        
        # Get blockchain details if proof is batched
        tx_hash = 'Pending'
        merkle_root = None
        batch_id = None
        aggregated_signature = None
        block_number = None
        gas_used = None
        anchored_at = None
        
        if proof.batch:
            batch_id = proof.batch.batch_id
            merkle_root = proof.batch.merkle_root
            aggregated_signature = proof.batch.aggregated_signature
            tx_hash = proof.batch.tx_hash if proof.batch.tx_hash else 'Pending'
            block_number = proof.batch.block_number if proof.batch.block_number else None
            gas_used = proof.batch.gas_used if hasattr(proof.batch, 'gas_used') else None
            anchored_at = proof.batch.anchored_at if proof.batch.anchored_at else None
            
            # If batch is anchored but tx_hash is None, try to get from blockchain transaction
            if proof.batch.status == 'anchored' and (not tx_hash or tx_hash == 'Pending'):
                from app.models import BlockchainTransaction
                blockchain_tx = BlockchainTransaction.objects.filter(related_batch=proof.batch).order_by('-created_at').first()
                if blockchain_tx:
                    tx_hash = blockchain_tx.tx_hash
                    block_number = blockchain_tx.block_number if blockchain_tx.block_number else block_number
                    gas_used = blockchain_tx.gas_used if blockchain_tx.gas_used else gas_used
        
        proof_data.append({
            'proof': proof,
            'status': status,
            'status_display': status_display,
            'emoji': emoji,
            'safety_score': round(proof.safety_score * 100, 1),
            'agent_name': proof.agent.name,
            'agent_did': proof.agent.did if proof.agent.did else 'N/A',
            'tx_hash': tx_hash,
            'merkle_root': merkle_root,
            'batch_id': batch_id,
            'aggregated_signature': aggregated_signature,
            'block_number': block_number,
            'gas_used': gas_used,
            'anchored_at': anchored_at,
        })
    
    context = {
        'user': user,
        'proofs': proof_data,
        'page_obj': page_obj,          # For pagination controls
        'paginator': paginator,        # For total count
        'total_queries': total_queries,
        'verified_queries': verified_queries,
        'pending_queries': pending_queries,
        'verification_rate': verification_rate,
        'agents': user_agents,
        'search': search,
        'agent_filter': agent_filter,
        'status_filter': status_filter,
        'date_filter': date_filter,
    }
    
    return render(request, 'user/my_history.html', context)


def verify_single_proof_view(request, proof_id):
    """
    Verify a single PoCA proof immediately on the blockchain.
    This bypasses the Mithril batch process for instant verification.
    """
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})
    
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id, submitted_by=user)
    except PoCAProof.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Proof not found'})
    
    if proof.is_batched:
        return JsonResponse({'success': False, 'message': 'Proof already batched or verified'})
    
    
    
    # Verify the cryptographic PoCA signature before blockchain anchoring.
    if not verify_poca_signature_onchain(proof):
        return JsonResponse(
            {
                'success': False,
                'message': 'PoCA signature verification failed. Proof was not anchored.',
            },
            status=400,
        )
        
    if proof.accepted_at is None:
        return JsonResponse(
            {
                "success": False,
                "message": "Proof has not passed intake acceptance.",
            },
            status=409,
        )
    
    try:
        from .crypto_utils import build_merkle_tree, generate_batch_id
        from .blockchain.logic import addNewData
        from django.utils import timezone
        from django.db import transaction
        
        # Build Merkle tree for single proof
        leaves = [proof.signature]
        merkle_result = build_merkle_tree(leaves)
        
        if not merkle_result or not merkle_result.get('root'):
            return JsonResponse({'success': False, 'message': 'Failed to build Merkle tree'})
        
        # Generate batch ID for single proof
        batch_id = generate_batch_id()
        anchor_time = timezone.now()
        
        # Get agent info
        agent_info = {
            "agent_id": proof.agent.agent_id,
            "agent_name": proof.agent.name,
            "did": proof.agent.did,
            "model_hash": proof.agent.model_hash,
        }
        
        # Prepare data for blockchain
        data = {
            "type": "mithril_batch",
            "batch_id": batch_id,
            "agents": [agent_info],
            "merkle_root": merkle_result['root'],
            "aggregated_signature": proof.signature,
            "num_proofs": 1,
            "timestamp": anchor_time.isoformat(),
            "proof_id": proof.proof_id,
            "query_text": proof.query_text[:100],
            "safety_score": proof.safety_score,
        }
        
        # Re-fetch and revalidate the actual proof before anchoring.
        proof.refresh_from_db()

        if proof.is_batched:
            return JsonResponse(
                {
                    "success": False,
                    "message": "Proof has already been batched or verified.",
                },
                status=409,
            )

        if not verify_poca_signature_onchain(proof):
            return JsonResponse(
                {
                    "success": False,
                    "message": (
                        "PoCA signature verification failed. "
                        "Proof was not anchored."
                    ),
                },
                status=400,
            )
            
        # Anchor to blockchain
        result = addNewData(data)
        
        if result["success"]:
            with transaction.atomic():
                # Create the batch
                batch = MithrilBatch.objects.create(
                    batch_id=batch_id,
                    merkle_root=merkle_result['root'],
                    aggregated_signature=proof.signature,
                    num_proofs=1,
                    status='anchored',
                    tx_hash=result["tx_hash"],
                    block_number=result["block_number"],
                    anchored_at=anchor_time,
                )
                
                # Update proof with batch
                proof.batch = batch
                proof.is_batched = True
                proof.save()
                
                # Create blockchain transaction record
                tx_record = BlockchainTransaction.objects.create(
                    tx_hash=result["tx_hash"],
                    tx_type='batch_anchor',
                    related_batch=batch,
                    block_number=result["block_number"],
                    gas_used=result["gas_used"],
                    status='success'
                )
                tx_record.related_agents.add(proof.agent)
            
            return JsonResponse({
                'success': True,
                'message': f'Proof {proof_id} verified and anchored on blockchain!',
                'tx_hash': result["tx_hash"],
                'block_number': result["block_number"],
                'merkle_root': merkle_result['root'],
                'batch_id': batch_id,
                'gas_used': result["gas_used"],
                'anchored_at': anchor_time.isoformat(),
                'aggregated_signature': proof.signature,
            })
        else:
            return JsonResponse({
                'success': False,
                'message': f'Blockchain anchoring failed: {result.get("error", "Unknown error")}'
            })
                
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'message': str(e)})


def delete_history_item_view(request, proof_id):
    #Delete a history item (PoCA proof)
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid method'})
    
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})
    
    try:
        proof = PoCAProof.objects.get(id=proof_id, submitted_by=user)
        proof.delete()
        return JsonResponse({'success': True, 'message': 'Deleted successfully'})
    except PoCAProof.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Proof not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


from django.http import HttpResponse
from datetime import datetime
import csv
import json
def download_response_view(request, proof_id):
    #Download a single response as text file
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to download.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    try:
        # Get proof by proof_id field (string)
        proof = PoCAProof.objects.get(proof_id=proof_id, submitted_by=user)
        
        # Create response
        response = HttpResponse(content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="response_{proof.proof_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"'
        
        content = f"""
            ===============================================================================
            SECUREAI PLATFORM - RESPONSE DOWNLOAD
            ===============================================================================
            
            PROOF ID: {proof.proof_id}
            AGENT: {proof.agent.name}
            SUBMITTED BY: {proof.submitted_by.username}
            CREATED: {proof.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            SAFETY SCORE: {proof.safety_score * 100:.1f}%
            STATUS: {'Verified' if proof.is_batched else 'Pending'}
            
            ===============================================================================
            QUERY
            ===============================================================================
            {proof.query_text}
            
            ===============================================================================
            RESPONSE
            ===============================================================================
            {proof.ai_response}
            
            ===============================================================================
            CRYPTOGRAPHIC PROOF
            ===============================================================================
            Context Hash: {proof.context_hash}
            Model Hash: {proof.model_hash}
            Signature: {proof.signature[:100]}...
            ===============================================================================
        """
        
        response.write(content)
        return response
        
    except PoCAProof.DoesNotExist:
        messages.error(request, f'Proof {proof_id} not found.')
        return redirect('my_history')
    except Exception as e:
        messages.error(request, f'Error downloading: {str(e)}')
        return redirect('my_history')


def export_all_history_view(request):
    #Export all user history as CSV
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to export.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    # Get all user proofs
    proofs = PoCAProof.objects.filter(submitted_by=user).select_related('agent').order_by('-created_at')
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="history_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    
    # Write header
    writer.writerow([
        'Proof ID', 'Agent', 'Query', 'Response', 'Safety Score', 
        'Status', 'Created At', 'Context Hash', 'Model Hash'
    ])
    
    # Write data
    for proof in proofs:
        status = 'Verified' if proof.is_batched else 'Pending'
        writer.writerow([
            proof.proof_id,
            proof.agent.name,
            proof.query_text[:200] + '...' if len(proof.query_text) > 200 else proof.query_text,
            proof.ai_response[:200] + '...' if len(proof.ai_response) > 200 else proof.ai_response,
            f"{proof.safety_score * 100:.1f}%",
            status,
            proof.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            proof.context_hash,
            proof.model_hash
        ])
    
    return response


def export_history_json_view(request):
    #Export all user history as JSON
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to export.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    # Get all user proofs
    proofs = PoCAProof.objects.filter(submitted_by=user).select_related('agent').order_by('-created_at')
    
    data = []
    for proof in proofs:
        data.append({
            'proof_id': proof.proof_id,
            'agent': proof.agent.name,
            'query': proof.query_text,
            'response': proof.ai_response,
            'safety_score': proof.safety_score,
            'safety_percent': f"{proof.safety_score * 100:.1f}%",
            'status': 'Verified' if proof.is_batched else 'Pending',
            'created_at': proof.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'context_hash': proof.context_hash,
            'model_hash': proof.model_hash,
            'signature': proof.signature[:50] + '...' if proof.signature else ''
        })
    
    response = HttpResponse(json.dumps(data, indent=2), content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="history_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
    return response


def verified_responses_view(request):
    #Display all blockchain-verified responses for the user
    # Check if user is authenticated
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to view verified responses.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    # Get filter parameters
    search = request.GET.get('search', '').strip()
    agent_filter = request.GET.get('agent', '')
    date_filter = request.GET.get('date', '')
    
    # Base queryset - only user's verified responses (batched and safety score >= 0.7)
    proofs = PoCAProof.objects.filter(
        submitted_by=user,
        is_batched=True,
        safety_score__gte=0.7
    ).select_related('agent', 'batch')
    
    # Apply filters
    if search:
        proofs = proofs.filter(
            django_models.Q(proof_id__icontains=search) |
            django_models.Q(query_text__icontains=search) |
            django_models.Q(agent__name__icontains=search)
        )
    
    if agent_filter:
        proofs = proofs.filter(agent__id=agent_filter)
    
    if date_filter:
        from datetime import datetime, timedelta
        today = datetime.now().date()
        if date_filter == 'today':
            proofs = proofs.filter(created_at__date=today)
        elif date_filter == 'week':
            week_ago = today - timedelta(days=7)
            proofs = proofs.filter(created_at__date__gte=week_ago)
        elif date_filter == 'month':
            month_ago = today - timedelta(days=30)
            proofs = proofs.filter(created_at__date__gte=month_ago)
    
    # Order by newest first
    proofs = proofs.order_by('-created_at')
    
    # Calculate stats
    total_verified = PoCAProof.objects.filter(submitted_by=user, is_batched=True, safety_score__gte=0.7).count()
    
    # Calculate average safety score
    verified_proofs = PoCAProof.objects.filter(submitted_by=user, is_batched=True, safety_score__gte=0.7)
    avg_safety = round(sum([p.safety_score for p in verified_proofs]) / len(verified_proofs) * 100 if verified_proofs else 0, 1)
    
    # Get unique agents count
    unique_agents = verified_proofs.values('agent').distinct().count()
    
    # Get all agents for filter dropdown (only those user has used with verified responses)
    user_agents = Agent.objects.filter(proofs__submitted_by=user, proofs__is_batched=True).distinct().order_by('name')
    
    # Prepare proof data
    proof_data = []
    for proof in proofs:
        # Get agent emoji based on name
        agent_name = proof.agent.name.lower()
        if 'medical' in agent_name or 'health' in agent_name:
            emoji = '🏥'
        elif 'code' in agent_name or 'review' in agent_name:
            emoji = '💻'
        elif 'data' in agent_name or 'analytics' in agent_name:
            emoji = '📊'
        elif 'legal' in agent_name or 'law' in agent_name:
            emoji = '⚖️'
        elif 'finance' in agent_name or 'investment' in agent_name:
            emoji = '💰'
        else:
            emoji = '🤖'
        
        # Get blockchain transaction details through the batch
        tx_hash = 'Pending'
        block_number = '—'
        gas_used = '—'
        merkle_root = '—'
        aggregated_signature = '—'
        anchored_at = None
        batch_id = None
        
        if proof.batch:
            batch_id = proof.batch.batch_id
            merkle_root = proof.batch.merkle_root if proof.batch.merkle_root else '—'
            aggregated_signature = proof.batch.aggregated_signature if proof.batch.aggregated_signature else '—'
            
            from app.models import BlockchainTransaction
            blockchain_tx = BlockchainTransaction.objects.filter(related_batch=proof.batch).order_by('-created_at').first()
            if blockchain_tx:
                tx_hash = blockchain_tx.tx_hash
                block_number = blockchain_tx.block_number if blockchain_tx.block_number else '—'
                gas_used = blockchain_tx.gas_used if blockchain_tx.gas_used else '—'
                # Use created_at as anchored_at if available, or skip
                if hasattr(blockchain_tx, 'created_at'):
                    anchored_at = blockchain_tx.created_at
            elif proof.batch.anchored_at:
                tx_hash = 'Anchored (Tx Pending)'
                anchored_at = proof.batch.anchored_at
        
        proof_data.append({
            'proof': proof,
            'emoji': emoji,
            'safety_percent': round(proof.safety_score * 100, 1),
            'safety_class': 'high' if proof.safety_score >= 0.7 else ('medium' if proof.safety_score >= 0.4 else 'low'),
            'agent_did': proof.agent.did if proof.agent.did else 'N/A',
            'tx_hash': tx_hash,
            'block_number': block_number,
            'gas_used': gas_used,
            'merkle_root': merkle_root,
            'aggregated_signature': aggregated_signature,
            'anchored_at': anchored_at,
            'batch_id': batch_id,
        })
    
    context = {
        'user': user,
        'proofs': proof_data,
        'total_verified': total_verified,
        'avg_safety': avg_safety,
        'unique_agents': unique_agents,
        'agents': user_agents,
        'search': search,
        'agent_filter': agent_filter,
        'date_filter': date_filter,
    }
    
    return render(request, 'user/verified_responses.html', context)


def download_verified_response_view(request, proof_id):
    #Download a single verified response as text file
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to download.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id, submitted_by=user, is_batched=True, safety_score__gte=0.7)
        
        response = HttpResponse(content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="verified_response_{proof.proof_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"'
        
        content = f"""
            ===============================================================================
            SECUREAI PLATFORM - VERIFIED RESPONSE DOWNLOAD
            ===============================================================================
            
            PROOF ID: {proof.proof_id}
            AGENT: {proof.agent.name}
            SUBMITTED BY: {proof.submitted_by.username}
            CREATED: {proof.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            SAFETY SCORE: {proof.safety_score * 100:.1f}%
            STATUS: VERIFIED ON BLOCKCHAIN
            
            ===============================================================================
            QUERY
            ===============================================================================
            {proof.query_text}
            
            ===============================================================================
            VERIFIED RESPONSE
            ===============================================================================
            {proof.ai_response}
            
            ===============================================================================
            BLOCKCHAIN PROOF DETAILS
            ===============================================================================
            Context Hash: {proof.context_hash}
            Model Hash: {proof.model_hash}
            Signature: {proof.signature[:100]}...
            ===============================================================================
        """
        
        response.write(content)
        return response
        
    except PoCAProof.DoesNotExist:
        messages.error(request, f'Verified proof {proof_id} not found.')
        return redirect('verified_responses')
    except Exception as e:
        messages.error(request, f'Error downloading: {str(e)}')
        return redirect('verified_responses')


def export_verified_responses_view(request):
    #Export all verified responses as CSV"""
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to export.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    proofs = PoCAProof.objects.filter(
        submitted_by=user,
        is_batched=True,
        safety_score__gte=0.7
    ).select_related('agent').order_by('-created_at')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="verified_responses_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Proof ID', 'Agent', 'Query', 'Verified Response', 'Safety Score', 'Created At', 'Context Hash', 'Model Hash', 'Status'])
    
    for proof in proofs:
        writer.writerow([
            proof.proof_id,
            proof.agent.name,
            proof.query_text[:200] + '...' if len(proof.query_text) > 200 else proof.query_text,
            proof.ai_response[:200] + '...' if len(proof.ai_response) > 200 else proof.ai_response,
            f"{proof.safety_score * 100:.1f}%",
            proof.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            proof.context_hash,
            proof.model_hash,
            'Verified on Blockchain'
        ])
    
    return response


def export_verified_responses_json_view(request):
    #Export all verified responses as JSON
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to export.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    proofs = PoCAProof.objects.filter(
        submitted_by=user,
        is_batched=True,
        safety_score__gte=0.7
    ).select_related('agent').order_by('-created_at')
    
    data = []
    for proof in proofs:
        data.append({
            'proof_id': proof.proof_id,
            'agent': proof.agent.name,
            'query': proof.query_text,
            'verified_response': proof.ai_response,
            'safety_score': proof.safety_score,
            'safety_percent': f"{proof.safety_score * 100:.1f}%",
            'status': 'Verified on Blockchain',
            'created_at': proof.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'context_hash': proof.context_hash,
            'model_hash': proof.model_hash,
            'signature': proof.signature[:50] + '...' if proof.signature else ''
        })
    
    response = HttpResponse(json.dumps(data, indent=2), content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="verified_responses_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
    return response


def available_agents_view(request):
    #Display all active AI agents available for users
    # Check if user is authenticated
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to view available agents.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    # Get filter parameters
    search = request.GET.get('search', '').strip()
    provider = request.GET.get('provider', '')
    category = request.GET.get('category', '')
    
    # Base queryset - only active agents
    agents = Agent.objects.filter(status='active')
    
    # Apply filters
    if search:
        agents = agents.filter(
            django_models.Q(name__icontains=search) |
            django_models.Q(agent_id__icontains=search) |
            django_models.Q(description__icontains=search)
        )
    
    if provider:
        agents = agents.filter(llm_provider=provider)
    
    # Category filter (based on description keywords)
    if category:
        category_map = {
            'medical': ['medical', 'health', 'clinical', 'patient'],
            'code': ['code', 'review', 'debug', 'security', 'programming'],
            'data': ['data', 'analytics', 'analysis', 'trend', 'visualization'],
            'legal': ['legal', 'law', 'contract', 'compliance', 'document'],
            'finance': ['finance', 'financial', 'investment', 'market', 'portfolio'],
            'general': ['general', 'assistant', 'versatile'],
        }
        keywords = category_map.get(category, [])
        if keywords:
            query = django_models.Q()
            for keyword in keywords:
                query |= django_models.Q(description__icontains=keyword)
            agents = agents.filter(query)
    
    # Order by newest first
    agents = agents.order_by('-created_at')
    
    # Calculate stats
    total_agents = agents.count()
    total_providers = agents.values('llm_provider').distinct().count()
    
    # Calculate average verification rate (mock for now - will be calculated from proofs)
    # In real implementation, you'd calculate this from PoCAProof data
    avg_verification_rate = 98.7  # Placeholder
    
    # For each agent, get proof count and verification rate
    for agent in agents:
        agent.proof_count = PoCAProof.objects.filter(agent=agent).count()
        # Calculate verification rate based on batched proofs
        total_proofs = PoCAProof.objects.filter(agent=agent).count()
        batched_proofs = PoCAProof.objects.filter(agent=agent, is_batched=True).count()
        agent.verification_rate = round((batched_proofs / total_proofs * 100) if total_proofs > 0 else 0, 1)
    
    context = {
        'user': user,
        'agents': agents,
        'total_agents': total_agents,
        'total_providers': total_providers,
        'avg_verification_rate': avg_verification_rate,
        'search': search,
        'provider_filter': provider,
        'category_filter': category,
    }
    
    return render(request, 'user/available_agents.html', context)


def verification_status_view(request):
    #Verification Status page with dynamic data from database
    # Check if user is authenticated
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to view verification status.')
        return redirect('index')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        request.session.flush()
        messages.error(request, 'Session expired. Please login again.')
        return redirect('index')
    
    # Get recent verifications for the user (last 5)
    recent_proofs = PoCAProof.objects.filter(
        submitted_by=user
    ).select_related('agent', 'batch').order_by('-created_at')[:5]
    
    # Prepare recent verifications data
    recent_verifications = []
    for proof in recent_proofs:
        # Determine status
        if proof.is_batched and proof.safety_score >= 0.7:
            status = 'verified'
            status_display = 'Verified'
        elif proof.is_batched:
            status = 'verified'
            status_display = 'Verified'
        elif proof.safety_score == 0.0:
            status = 'processing'
            status_display = 'Processing'
        elif proof.safety_score < 0.5:
            status = 'failed'
            status_display = 'Failed'
        else:
            status = 'pending'
            status_display = 'Pending'
        
        # Get agent emoji
        agent_name = proof.agent.name.lower()
        if 'medical' in agent_name or 'health' in agent_name:
            emoji = '🏥'
        elif 'code' in agent_name or 'review' in agent_name:
            emoji = '💻'
        elif 'data' in agent_name or 'analytics' in agent_name:
            emoji = '📊'
        elif 'legal' in agent_name or 'law' in agent_name:
            emoji = '⚖️'
        elif 'finance' in agent_name or 'investment' in agent_name:
            emoji = '💰'
        else:
            emoji = '🤖'
        
        # Get blockchain details if proof is batched
        tx_hash = 'Pending'
        block_number = '—'
        merkle_root = '—'
        aggregated_signature = '—'
        
        if proof.batch:
            merkle_root = proof.batch.merkle_root if proof.batch.merkle_root else '—'
            aggregated_signature = proof.batch.aggregated_signature if proof.batch.aggregated_signature else '—'
            tx_hash = proof.batch.tx_hash if proof.batch.tx_hash else 'Pending'
            block_number = proof.batch.block_number if proof.batch.block_number else '—'
            
            # If batch is anchored but tx_hash is None, try to get from blockchain transaction
            if proof.batch.status == 'anchored' and (not tx_hash or tx_hash == 'Pending'):
                from app.models import BlockchainTransaction
                blockchain_tx = BlockchainTransaction.objects.filter(related_batch=proof.batch).order_by('-created_at').first()
                if blockchain_tx:
                    tx_hash = blockchain_tx.tx_hash
                    block_number = blockchain_tx.block_number if blockchain_tx.block_number else block_number
        
        recent_verifications.append({
            'proof': proof,
            'status': status,
            'status_display': status_display,
            'emoji': emoji,
            'safety_percent': round(proof.safety_score * 100, 1),
            'agent_did': proof.agent.did if proof.agent.did else 'N/A',
            'tx_hash': tx_hash,
            'block_number': block_number,
            'merkle_root': merkle_root,
            'aggregated_signature': aggregated_signature,
            'batch_id': proof.batch.batch_id if proof.batch else None,
        })
    
    # Calculate stats
    total_verifications = PoCAProof.objects.filter(submitted_by=user).count()
    verified_count = PoCAProof.objects.filter(
        submitted_by=user,
        is_batched=True,
        safety_score__gte=0.7
    ).count()
    pending_count = PoCAProof.objects.filter(
        submitted_by=user,
        is_batched=False
    ).count()
    failed_count = PoCAProof.objects.filter(
        submitted_by=user,
        is_batched=False,
        safety_score__lt=0.5
    ).count()
    
    # For the search functionality - get the specific proof if ID is provided
    search_proof_id = request.GET.get('proof_id', '')
    searched_proof = None
    searched_proof_data = None
    
    if search_proof_id:
        try:
            proof = PoCAProof.objects.get(
                proof_id=search_proof_id,
                submitted_by=user
            )
            searched_proof = proof
            
            # Get blockchain details for searched proof
            tx_hash = 'Pending'
            block_number = '—'
            merkle_root = '—'
            aggregated_signature = '—'
            batch_id = None
            
            if proof.batch:
                batch_id = proof.batch.batch_id
                merkle_root = proof.batch.merkle_root if proof.batch.merkle_root else '—'
                aggregated_signature = proof.batch.aggregated_signature if proof.batch.aggregated_signature else '—'
                tx_hash = proof.batch.tx_hash if proof.batch.tx_hash else 'Pending'
                block_number = proof.batch.block_number if proof.batch.block_number else '—'
                
                if proof.batch.status == 'anchored' and (not tx_hash or tx_hash == 'Pending'):
                    from app.models import BlockchainTransaction
                    blockchain_tx = BlockchainTransaction.objects.filter(related_batch=proof.batch).order_by('-created_at').first()
                    if blockchain_tx:
                        tx_hash = blockchain_tx.tx_hash
                        block_number = blockchain_tx.block_number if blockchain_tx.block_number else block_number
            
            # Determine status for searched proof
            if proof.is_batched and proof.safety_score >= 0.7:
                search_status = 'verified'
                search_status_display = 'Verified'
            elif proof.is_batched:
                search_status = 'verified'
                search_status_display = 'Verified'
            elif proof.safety_score == 0.0:
                search_status = 'processing'
                search_status_display = 'Processing'
            elif proof.safety_score < 0.5:
                search_status = 'failed'
                search_status_display = 'Failed'
            else:
                search_status = 'pending'
                search_status_display = 'Pending'
            
            searched_proof_data = {
                'proof': proof,
                'status': search_status,
                'status_display': search_status_display,
                'agent_did': proof.agent.did if proof.agent.did else 'N/A',
                'tx_hash': tx_hash,
                'block_number': block_number,
                'merkle_root': merkle_root,
                'aggregated_signature': aggregated_signature,
                'batch_id': batch_id,
                'safety_percent': round(proof.safety_score * 100, 1),
            }
            
        except PoCAProof.DoesNotExist:
            searched_proof = None
            searched_proof_data = None
    
    context = {
        'user': user,
        'recent_verifications': recent_verifications,
        'total_verifications': total_verifications,
        'verified_count': verified_count,
        'pending_count': pending_count,
        'failed_count': failed_count,
        'searched_proof': searched_proof,
        'searched_proof_data': searched_proof_data,
        'search_proof_id': search_proof_id,
    }
    
    return render(request, 'user/verification_status.html', context)


def download_verification_report_view(request, proof_id):
    #Download a verification report as text file"""
    if not request.session.get('is_authenticated', False):
        messages.error(request, 'Please login to download.')
        return redirect('login')
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('login')
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id, submitted_by=user)
        
        # Determine status
        if proof.is_batched and proof.safety_score >= 0.7:
            status = 'VERIFIED ON BLOCKCHAIN'
        elif proof.is_batched:
            status = 'VERIFIED ON BLOCKCHAIN'
        elif proof.safety_score == 0.0:
            status = 'PROCESSING'
        elif proof.safety_score < 0.5:
            status = 'FAILED'
        else:
            status = 'PENDING'
        
        response = HttpResponse(content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="verification_report_{proof.proof_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"'
        
        content = f"""
            ===============================================================================
            SECUREAI PLATFORM - VERIFICATION REPORT
            ===============================================================================
            
            PROOF ID: {proof.proof_id}
            AGENT: {proof.agent.name}
            SUBMITTED BY: {proof.submitted_by.username}
            CREATED: {proof.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            SAFETY SCORE: {proof.safety_score * 100:.1f}%
            STATUS: {status}
            
            ===============================================================================
            BLOCKCHAIN VERIFICATION DETAILS
            ===============================================================================
            Transaction Hash: {proof.batch.tx_hash if proof.is_batched and proof.batch else 'Pending'}
            Block Number: {proof.batch.block_number if proof.is_batched and proof.batch else 'Pending'}
            Batch ID: {proof.batch.batch_id if proof.is_batched and proof.batch else 'Pending'}
            Merkle Root: {proof.batch.merkle_root if proof.is_batched and proof.batch else 'Pending'}
            Context Hash: {proof.context_hash}
            Model Hash: {proof.model_hash}
            Signature: {proof.signature[:100]}...
            
            ===============================================================================
            QUERY
            ===============================================================================
            {proof.query_text}
            
            ===============================================================================
            RESPONSE
            ===============================================================================
            {proof.ai_response}
            
            ===============================================================================
            VERIFICATION STEPS
            ===============================================================================
            Step 1: Proof Submission - {'Completed' if proof.created_at else 'Pending'}
            Step 2: Cryptographic Signing - {'Completed' if proof.signature else 'Pending'}
            {'' if proof.is_batched else ''} Step 3: Mithril Batch Aggregation - {'Completed' if proof.is_batched else 'Pending'}
            {'' if proof.is_batched else ''} Step 4: Merkle Tree Construction - {'Completed' if proof.is_batched else 'Pending'}
            {'' if proof.is_batched and proof.safety_score >= 0.7 else ''} Step 5: On-Chain Anchoring - {'Completed' if proof.is_batched and proof.safety_score >= 0.7 else 'Pending'}
            ===============================================================================
            This report was generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            ===============================================================================
        """
        
        response.write(content)
        return response
        
    except PoCAProof.DoesNotExist:
        messages.error(request, f'Proof {proof_id} not found.')
        return redirect('verification_status')
    except Exception as e:
        messages.error(request, f'Error downloading: {str(e)}')
        return redirect('verification_status')


def share_verification_view(request, proof_id):
    #Share verification - generates a shareable link
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id, submitted_by=user)
        
        share_url = f"{settings.BASE_URL}/verification-status/?proof_id={proof.proof_id}"
        
        return JsonResponse({
            'success': True,
            'share_url': share_url,
            'proof_id': proof.proof_id,
            'message': 'Share link generated successfully'
        })
        
    except PoCAProof.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Proof not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


def view_on_explorer_view(request, proof_id):
    """
    View transaction on blockchain explorer.
    FIXED: previously returned a hardcoded fake transaction hash for
    every single proof. Now it uses the REAL tx_hash stored on the
    proof's actual Mithril batch — the one that genuinely anchored it
    on Ganache.
    """
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id, submitted_by=user)
        
        if not proof.is_batched or not proof.batch:
            return JsonResponse({
                'success': False,
                'message': 'Proof is not yet anchored on blockchain'
            })
            
        if not proof.batch.tx_hash:
            return JsonResponse({
                'success': False,
                'message': 'This proof\'s batch has no recorded transaction hash'
            })
            
        explorer_url = f"http://127.0.0.1:7545/transaction/{proof.batch.tx_hash}"
        
        return JsonResponse({
            'success': True,
            'explorer_url': explorer_url,
            'tx_hash': proof.batch.tx_hash,
            'batch_id': proof.batch.batch_id,
            'block_number': proof.batch.block_number,
            'message': 'Explorer opened successfully'
        })
        
    except PoCAProof.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Proof not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


def verify_batch_view(request, batch_id):
    """
    Genuine tamper-evidence check for a Mithril batch.
    This is the actual proof of your thesis's core claim: it recomputes
    the Merkle root from the proofs currently stored in SQLite, and
    compares it against the batch's stored merkle_root (the same value
    that was anchored on-chain via addNewData()).
    - If nobody has touched the proof rows since batching: MATCH.
    - If anyone edits so much as one signature or proof row afterward:
    the recomputed root changes and this returns MISMATCH — proving
    tampering is detectable.
    Returns JSON (not a rendered page) so it can be called from a modal
    on the same Mithril Batches page, without navigating away.
    """
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Please login to verify a batch.'})
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session expired. Please login again.'})
    try:
        batch = MithrilBatch.objects.get(batch_id=batch_id)
    except MithrilBatch.DoesNotExist:
        return JsonResponse({'success': False, 'message': f'Batch {batch_id} not found.'})
    # Pull the exact proofs that were included in this batch, in the
    # same order they were originally batched (created_at, pk -- this
    # MUST match the ordering used in _reserve_proofs_for_batch()).
    batch_proofs = list(
        PoCAProof.objects.filter(batch=batch).order_by('created_at', 'pk')
    )
    result = {
        'success': True,
        'batch_id': batch.batch_id,
        'stored_merkle_root': batch.merkle_root,
        'recomputed_merkle_root': None,
        'match': False,
        'proof_count_expected': batch.num_proofs,
        'proof_count_found': len(batch_proofs),
        'tx_hash': batch.tx_hash,
        'block_number': batch.block_number,
        'status': batch.status,
        'proofs': [],
        'error': None,
    }
    # Sanity check: did any proofs go missing since batching?
    if len(batch_proofs) != batch.num_proofs:
        result['error'] = (
            f"Expected {batch.num_proofs} proofs in this batch, "
            f"but found {len(batch_proofs)} currently linked to it. "
            "This alone is evidence of tampering (a proof was likely "
            "deleted or unlinked)."
        )
    else:
        try:
            # Recompute the Merkle root fresh, from what's in SQLite RIGHT NOW.
            leaves = [proof.signature for proof in batch_proofs]
            merkle_result = build_merkle_tree(leaves)
            recomputed_root = merkle_result.get('root')
            result['recomputed_merkle_root'] = recomputed_root
            result['match'] = (recomputed_root == batch.merkle_root)
            for proof in batch_proofs:
                result['proofs'].append({
                    'proof_id': proof.proof_id,
                    'signature_preview': (proof.signature or '')[:24] + '...',
                })
        except Exception as exc:
            result['error'] = f"Recomputation failed: {exc}"
    return JsonResponse(result)



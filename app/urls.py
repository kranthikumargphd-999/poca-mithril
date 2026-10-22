from django.urls import path
from django.views.generic import TemplateView
from .views import *
from .attack_views import *

urlpatterns = [
    # Landing Page
    path('', landing_page, name='index'),
    
    # Authentication
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    
    # Admin actions
    path('admin-dashboard/', admin_dashboard_view, name='admin_dashboard'),
    path('agents/', agents_list_view, name='agents_list'),
    path('add-agent/', add_agent_view, name='add_agent'),
    path('edit-agent/<int:agent_id>/', edit_agent_view, name='edit_agent'),
    path('delete-agent/<int:agent_id>/', delete_agent_view, name='delete_agent'),
    
    # USERS CRUD 
    path('users/', users_list_view, name='users_list'),
    path('users/add/', add_user_view, name='add_user'),
    path('users/<int:user_id>/edit/', edit_user_view, name='edit_user'),
    path('users/<int:user_id>/toggle/', toggle_user_view, name='toggle_user'),
    path('users/<int:user_id>/delete/', delete_user_view, name='delete_user'),
    
    # POCA
    path('poca-proofs/', poca_proofs_view, name='poca_proofs'),
    path('delete-proof/<int:proof_id>/', delete_proof_view, name='delete_proof'),
    
    # MITHRIL
    path('mithril-batches/', mithril_batches_view, name='mithril_batches'),
    path('process-batches/', process_batches_view, name='process_batches'),
    path('anchor-batch/<str:batch_id>/', anchor_batch_view, name='anchor_batch'),
    path('retry-batch/<str:batch_id>/', retry_batch_view, name='retry_batch'),
    path('verify-batch/<str:batch_id>/', verify_batch_view,   name='verify_batch'),
    path('delete-batch/<int:batch_id>/', delete_batch_view, name='delete_batch'),
    path('export-batch/<int:batch_id>/', export_batch_view, name='export_batch'),
    
    # Blockchain TX 
    path('blockchain-tx/', blockchain_tx_view, name='blockchain_tx'),
    path('reports/', reports_view, name='reports'),
    path('generate-report/<str:report_type>/', generate_report, name='generate_report'),
    
    # ATTACK SCENARIO TESTING 
    path('test-attack/<int:scenario_id>/', test_attack_scenario, name='test_attack_scenario'),
    path('api/attack-logs/', get_attack_logs, name='attack_logs'),
    path('api/agents/', get_agents_api, name='api_agents'),
    path('api/recent-proofs/', get_recent_proofs_api, name='api_recent_proofs'),
    path('attack-logs/', attack_logs_page_view, name='attack_logs_page'),
    
    #User actions
    path('user-dashboard/', user_dashboard_view, name='user_dashboard'),
    path('download-response/<str:proof_id>/', download_response_view, name='download_response'),
    
    # Submit query 
    path('submit-query/', submit_query_view, name='submit_query'),
    path('my-history/', my_history_view, name='my_history'),
    
    # SINGLE PROOF VERIFICATION 
    path('verify-single-proof/<str:proof_id>/', verify_single_proof_view, name='verify_single_proof'),
    path('delete-history-item/<int:proof_id>/', delete_history_item_view, name='delete_history_item'),
    path('download-response/<str:proof_id>/', download_response_view, name='download_response'),
    path('export-history/', export_all_history_view, name='export_history'),
    path('export-history-json/', export_history_json_view, name='export_history_json'),
    
    # verified responses  
    path('verified-responses/', verified_responses_view, name='verified_responses'),
    path('download-verified/<str:proof_id>/', download_verified_response_view, name='download_verified'),
    path('export-verified-csv/', export_verified_responses_view, name='export_verified_csv'),
    path('export-verified-json/', export_verified_responses_json_view, name='export_verified_json'),
    
    #agents 
    path('available-agents/', available_agents_view, name='available_agents'),
    
    #status 
    path('verification-status/', verification_status_view, name='verification_status'),
    path('download-verification/<str:proof_id>/', download_verification_report_view, name='download_verification'),
    path('share-verification/<str:proof_id>/', share_verification_view, name='share_verification'),
    path('view-explorer/<str:proof_id>/', view_on_explorer_view, name='view_explorer'),
    path('verify-batch/<str:batch_id>/', verify_batch_view, name='verify_batch'),
]
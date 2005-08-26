//
// System.Web.UI.WebControls.ImageButton.cs
//
// Authors:
//	Jordi Mas i Hernandez (jordi@ximian.com)
//
// (C) 2005 Novell, Inc (http://www.novell.com)
//
//
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System.Collections.Specialized;
using System.ComponentModel;

namespace System.Web.UI.WebControls {
	[DefaultEvent("Click")]
#if NET_2_0
	[Designer ("System.Web.UI.Design.WebControls.PreviewControlDesigner, " + Consts.AssemblySystem_Design, "System.ComponentModel.Design.IDesigner")]
#endif		
	public class ImageButton : Image, IPostBackDataHandler, IPostBackEventHandler
#if NET_2_0
	, IButtonControl
#endif	
	{

		private static readonly object ClickEvent = new object ();
		private static readonly object CommandEvent = new object ();
		private int pos_x, pos_y;

		public ImageButton ()
		{

		}

#if ONLY_1_1
		[Bindable(false)]
#endif		
		[DefaultValue(true)]
#if NET_2_0
		[Themeable (false)]
		public virtual
#else		
		public
#endif		
		bool CausesValidation {
			get {
				return ViewState.GetBool ("CausesValidation", true);
			}

			set {
				ViewState ["CausesValidation"] = value;
			}
		}

		[Bindable(true)]
		[DefaultValue("")]
#if NET_2_0
		[Themeable (false)]
		public virtual
#else		
		public
#endif		
		string CommandArgument {
			get {
				return ViewState.GetString ("CommandArgument", "");
			}
			set {
				ViewState ["CommandArgument"] = value;
			}
		}

		[DefaultValue("")]
#if NET_2_0
		[Themeable (false)]
		public virtual
#else		
		public
#endif		
		string CommandName {
			get {
				return ViewState.GetString ("CommandName", "");
			}
			set {
				ViewState ["CommandName"] = value;
			}
		}

#if NET_2_0
		[EditorBrowsable (EditorBrowsableState.Always)]
		[Browsable (true)]
		[DefaultValue ("")]
		[Bindable (true)]
		[MonoTODO]
		public virtual new bool Enabled
		{
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		[Browsable (false)]
		[EditorBrowsable (EditorBrowsableState.Never)]
		[Themeable (false)]
		[DesignerSerializationVisibility (DesignerSerializationVisibility.Hidden)]
		[MonoTODO]
		public virtual new bool GenerateEmptyAlternateText
		{
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		[DefaultValue ("")]
		[Themeable (false)]
		[MonoTODO]
		public virtual string OnClientClick 
		{
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		[Themeable (false)]
		[UrlProperty]
		[DefaultValue ("")]
		[Editor ("System.Web.UI.Design.UrlEditor, "  + Consts.AssemblySystem_Design, "System.Drawing.Design.UITypeEditor, " + Consts.AssemblySystem_Drawing)]
		[MonoTODO]
		public virtual string PostBackUrl
		{
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		[Themeable (false)]
		[DefaultValue ("")]
		public virtual string ValidationGroup
		{
			get {
				return ViewState.GetString ("ValidationGroup", "");
			}
			set {
				ViewState ["ValidationGroup"] = value;
			}
		}
#endif		

		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
#if NET_2_0 && HAVE_CONTROL_ADAPTERS
		protected virtual new
#else		
		protected override
#endif
		HtmlTextWriterTag TagKey {
			get { return HtmlTextWriterTag.Input; }
		}

#if NET_2_0
		[MonoTODO]
		protected virtual string Text 
		{
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}
#endif		

		protected override void AddAttributesToRender (HtmlTextWriter writer)
		{
			if (Page != null)
				Page.VerifyRenderingInServerForm (this);

			writer.AddAttribute (HtmlTextWriterAttribute.Type, "image");
			if (CausesValidation && Page != null && Page.AreValidatorsUplevel ()) {
				ClientScriptManager csm = new ClientScriptManager (Page);
				writer.AddAttribute (HtmlTextWriterAttribute.Onclick, csm.GetClientValidationEvent ());
				writer.AddAttribute ("language", "javascript");
			}
			base.AddAttributesToRender (writer);
		}

#if NET_2_0
		[MonoTODO]
		protected virtual PostBackOptions GetPostBackOptions ()
		{
			throw new NotImplementedException ();
		}
#endif		


#if NET_2_0
		[MonoTODO]
		protected virtual bool LoadPostData (string postDataKey, NameValueCollection psotCollection) 
		{
			throw new NotImplementedException ();
		}

		[MonoTODO]
		protected virtual void RaisePostDataChangedEvent ()
		{
			throw new NotImplementedException ();
		}
		
		[MonoTODO]
		protected virtual void RaisePostBackEvent (string eventArgument)
		{
			throw new NotImplementedException ();
		}
#endif

		bool IPostBackDataHandler.LoadPostData (string postDataKey,  NameValueCollection postCollection)
		{
			string x, y;

			x = postCollection [UniqueID + ".x"];
			y = postCollection [UniqueID + ".y"];

			if (x != null && y != null) {
				pos_x = Int32.Parse(x);
				pos_y = Int32.Parse(y);
				Page.RegisterRequiresRaiseEvent (this);
			}

			return true;
		}


		void IPostBackDataHandler.RaisePostDataChangedEvent ()
		{

		}

		void IPostBackEventHandler.RaisePostBackEvent (string eventArgument)
		{
			if (CausesValidation)
#if NET_2_0
				Page.Validate (ValidationGroup);
#else
				Page.Validate ();
#endif

			OnClick (new ImageClickEventArgs (pos_x, pos_y));
			OnCommand (new CommandEventArgs (CommandName, CommandArgument));
		}

		protected virtual void OnClick (ImageClickEventArgs e)
		{
			if (Events != null) {
				EventHandler eh = (EventHandler) (Events [ClickEvent]);
				if (eh != null)
					eh (this, e);
			}
		}

		protected virtual void OnCommand (CommandEventArgs e)
		{
			if (Events != null) {
				CommandEventHandler eh = (CommandEventHandler) (Events [CommandEvent]);
				if (eh != null)
					eh (this, e);
			}

			RaiseBubbleEvent (this, e);
		}

#if NET_2_0
		protected internal
#else		
		protected
#endif		
		override void OnPreRender (EventArgs e)
		{
			if (Page != null)
				Page.RegisterRequiresPostBack (this);
		}

		public event ImageClickEventHandler Click
		{
			add {
				Events.AddHandler (ClickEvent, value);
			}
			remove {
				Events.RemoveHandler (ClickEvent, value);
			}
		}

		public event CommandEventHandler Command
		{
			add {
				Events.AddHandler (CommandEvent, value);
			}
			remove {
				Events.RemoveHandler (CommandEvent, value);
			}
		}

#if NET_2_0
		[MonoTODO]
		string IButtonControl.Text 
		{
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		[MonoTODO]
		event EventHandler IButtonControl.Click
		{
			add {
				throw new NotImplementedException ();
			}
			remove {
				throw new NotImplementedException ();
			}
		}
		
#endif
	}
}

